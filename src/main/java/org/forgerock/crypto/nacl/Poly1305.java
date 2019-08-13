/*
 * Copyright 2019 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.forgerock.crypto.nacl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

final class Poly1305 {
    private static final int BLOCK_SIZE = 16;
    static final int TAG_SIZE = 16;

    static byte[] compute(byte[] key, byte[] data, int from, int to) {
        assert key.length == 32;

        // Read r and clamp
        UInt130ModP r = UInt130ModP.read(key, 0).clamp();

        int[] k = new int[4];
        ByteBuffer.wrap(key, 16, 16).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(k);

        UInt130ModP h = new UInt130ModP();

        for (int i = from; i < to; i += BLOCK_SIZE) {
            int highBit = (i + BLOCK_SIZE) > to ? 0 : (1 << 24);

            UInt130ModP m = UInt130ModP.read(data, i);
            m.limbs[4] |= highBit;

            h.plus(m);
            h.times(r);
        }

        // Full carry propagation and reduce mod P (in constant time)
        h.reduce();

        // Reduce h mod 2^128
        int[] tag = h.mod2_128();

        // tag = (h + k) mod 2^128
        long f = ul(tag[0]) + ul(k[0]);
        tag[0] = (int) f;
        f =  ul(tag[1]) + ul(k[1]) + (f >>> 32);
        tag[1] = (int) f;
        f = ul(tag[2]) + ul(k[2]) + (f >>> 32);
        tag[2] = (int) f;
        f = ul(tag[3]) + ul(k[3]) + (f >>> 32);
        tag[3] = (int) f;

        byte[] mac = new byte[16];
        ByteBuffer buffer = ByteBuffer.wrap(mac).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(tag[0]);
        buffer.putInt(tag[1]);
        buffer.putInt(tag[2]);
        buffer.putInt(tag[3]);

        return mac;
    }

    static boolean verify(byte[] key, byte[] data, byte[] tag) {
        byte[] computed = compute(key, data, 0, data.length);
        try {
            return Bytes.equal(computed, tag);
        } finally {
            Arrays.fill(computed, (byte) 0);
        }
    }

    private static long ul(int val) {
        return val & 0xFFFFFFFFL;
    }

    /**
     * Representation of an unsigned 130-bit integer (mod p) as 5 26-bit values. By using 32-bit integers for the
     * limbs we leave 6 bits free to reduce the number of times we have to perform carry propagation. This is the
     * standard representation used in efficient Poly1305 implementations.
     */
    private static final class UInt130ModP {
        private static final int LIMB_MASK = 0x03FFFFFF;
        private final int[] limbs;

        UInt130ModP(int[] limbs) {
            this.limbs = limbs;
        }
        UInt130ModP() {
            this(new int[5]);
        }

        static UInt130ModP read(byte[] data, int offset) {
            // Apply padding if data is too short. This should only be needed for the last message block.
            if (offset + 16 > data.length) {
                int diff = data.length - offset;
                data = Arrays.copyOfRange(data, offset, offset + 16);
                data[diff] = 1;
                offset = 0;
            }

            ByteBuffer buffer = ByteBuffer.wrap(data, offset, 16).order(ByteOrder.LITTLE_ENDIAN);
            int[] limbs = new int[5];
            int shift = 0;
            for (int i = 0; i < 5; ++i) {
                limbs[i] = (buffer.getInt() >>> shift) & LIMB_MASK;
                buffer.position(buffer.position() - 1);
                shift += 2;
            }
            return new UInt130ModP(limbs);
        }

        UInt130ModP clamp() {
            limbs[1] &= 0x03FFFF03;
            limbs[2] &= 0x03FFC0FF;
            limbs[3] &= 0x03F03FFF;
            limbs[4] &= 0x000FFFFF;
            return this;
        }

        void plus(UInt130ModP b) {
            limbs[0] += b.limbs[0];
            limbs[1] += b.limbs[1];
            limbs[2] += b.limbs[2];
            limbs[3] += b.limbs[3];
            limbs[4] += b.limbs[4];
        }

        void times(UInt130ModP b) {
            final long[] d = new long[5];
            final int[] h = limbs;
            final int[] r = b.limbs;
            final int[] s = { 1, r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5 };

            // h *= r
            d[0] = (ul(h[0]) * r[0]) + (ul(h[1]) * s[4]) + (ul(h[2]) * s[3]) + (ul(h[3]) * s[2]) + (ul(h[4]) * s[1]);
            d[1] = (ul(h[0]) * r[1]) + (ul(h[1]) * r[0]) + (ul(h[2]) * s[4]) + (ul(h[3]) * s[3]) + (ul(h[4]) * s[2]);
            d[2] = (ul(h[0]) * r[2]) + (ul(h[1]) * r[1]) + (ul(h[2]) * r[0]) + (ul(h[3]) * s[4]) + (ul(h[4]) * s[3]);
            d[3] = (ul(h[0]) * r[3]) + (ul(h[1]) * r[2]) + (ul(h[2]) * r[1]) + (ul(h[3]) * r[0]) + (ul(h[4]) * s[4]);
            d[4] = (ul(h[0]) * r[4]) + (ul(h[1]) * r[3]) + (ul(h[2]) * r[2]) + (ul(h[3]) * r[1]) + (ul(h[4]) * r[0]);

            // partial reduction of h mod p
            h[0] = (int) d[0] & LIMB_MASK;
            d[1] += (d[0] >>> 26);

            h[1] = (int) d[1] & LIMB_MASK;
            d[2] += (d[1] >>> 26);

            h[2] = (int) d[2] & LIMB_MASK;
            d[3] += (d[2] >>> 26);

            h[3] = (int) d[3] & LIMB_MASK;
            d[4] += (d[3] >>> 26);

            h[4] = (int) d[4] & LIMB_MASK;
            h[0] += (int) (d[4] >>> 26) * 5;

            h[1] += (h[0] >>> 26);
            h[0] = h[0] & LIMB_MASK;
        }

        void reduce() {
            final int[] h = limbs;

            // fully carry h
            h[1] += (h[0] >>> 26);
            h[0] &= LIMB_MASK;

            h[2] += (h[1] >>> 26);
            h[1] &= LIMB_MASK;

            h[3] += (h[2] >>> 26);
            h[2] &= LIMB_MASK;

            h[4] += (h[3] >>> 26);
            h[3] &= LIMB_MASK;

            h[0] += (h[4] >>> 26) * 5;
            h[4] &= LIMB_MASK;

            h[1] += (h[0] >>> 26);
            h[0] &= LIMB_MASK;

            // compute h-p
            int g0 = h[0] + 5;
            int c = g0 >>> 26;
            g0 &= LIMB_MASK;
            int g1 = h[1] + c;
            c = g1 >>> 26;
            g1 &= LIMB_MASK;
            int g2 = h[2] + c;
            c = g2 >>> 26;
            g2 &= LIMB_MASK;
            int g3 = h[3] + c;
            c = g3 >>> 26;
            g3 &= LIMB_MASK;
            int g4 = h[4] + c - (1 << 26);

            // select h if h < p or h-p if h >= p (in constant time)
            int mask = (g4 >>> 31) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            mask = ~mask;

            h[0] = (h[0] & mask) | g0;
            h[1] = (h[1] & mask) | g1;
            h[2] = (h[2] & mask) | g2;
            h[3] = (h[3] & mask) | g3;
            h[4] = (h[4] & mask) | g4;
        }

        int[] mod2_128() {
            int[] h = new int[4];

            h[0] = limbs[0] | (limbs[1] << 26);
            h[1] = (limbs[1] >>> 6) | (limbs[2] << 20);
            h[2] = (limbs[2] >>> 12) | (limbs[3] << 14);
            h[3] = (limbs[3] >>> 18) | (limbs[4] << 8);

            return h;
        }


        @Override
        public String toString() {
            UInt130ModP it = new UInt130ModP(limbs.clone());
            it.reduce();
            int[] vals = it.mod2_128();
            ByteBuffer out = ByteBuffer.allocate(17).order(ByteOrder.LITTLE_ENDIAN);
            out.asIntBuffer().put(vals);
            out.position(16);
            out.put((byte) ((limbs[4] >>> 24) & 0xFF));
            StringBuilder sb = new StringBuilder();
            for (int i = 16; i >= 0; --i) {
                sb.append(String.format("%02x", out.get(i) & 0xFF));
            }
            return sb.toString();
        }
    }
}
