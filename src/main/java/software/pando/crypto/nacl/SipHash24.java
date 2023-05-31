/*
 * Copyright 2023 Neil Madden.
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
 *
 * Portions copyright 2016 Pando Software Ltd.
 */

package software.pando.crypto.nacl;

import static java.util.Objects.requireNonNull;

import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * Implementation of the SipHash-2-4 fast, cryptographically strong pseudorandom function (PRF) designed to
 * be used as a general purpose hash algorithm to avoid hash-flooding DoS attacks. This implementation is competitive
 * in performance to other general-purpose Java hash algorithms such as MurmurHash, whilst having significantly
 * stronger cryptographic properties. In particular, it is much more difficult to predict and manufacture hash
 * collisions with SipHash so long as the key remains secret.
 * <p>
 * SipHash can also be used as a Message Authentication Code (MAC) for short messages, but be aware that the output
 * size (64 bits) is considered too small to be secure on its own in this usage. It is better to use a general-purpose
 * MAC for those cases, such as BLAKE2 or SHA-256, which have significantly larger output tag sizes. SipHash can be used
 * in cases where either the format precludes larger tag sizes (such as IP packet authentication) or where there are
 * other mitigations (e.g., rate limiting if only online attacks are possible).
 * <p>
 * A SipHash algorithm with <em>c</em> compression rounds and <em>f</em> finalization rounds is known as
 * SipHash-<em>c</em>-<em>f</em>. For instance, SipHash-2-4 has 2 compression rounds and 4 finalization rounds. This
 * is the default, as recommended by the SipHash authors and the only variant implemented here.
 * <p>
 * The algorithm is designed to work well with short inputs, typically less than 1KiB in size. The interface is
 * therefore designed to accept the input directly as a single byte array. It is not recommended to use it with
 * significantly larger inputs, as other hash algorithms will likely be faster.
 *
 * @see <a href="http://131002.net/siphash/">SipHash Website</a>
 */
final class SipHash24 {

    private SipHash24() {}

    /**
     * Computes a PRF tag for the given input data and the configured secret key.
     *
     * @param key the SipHash key.
     * @param input the input data.
     * @return the computed SipHash tag for the data using the configured key.
     */
    static byte[] hash(final SecretKey key, final byte[] input) {
        requireNonNull(key, "key");
        if (!"SipHash".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("Key is not intended for use with SipHash");
        }
        if (!"raw".equalsIgnoreCase(key.getFormat())) {
            throw new IllegalArgumentException("Only RAW format keys supported");
        }
        final byte[] keyBytes = key.getEncoded();
        if (keyBytes.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes exactly");
        }
        final long[] initialState = initialState();
        final long k0 = bytesToLong(keyBytes, 0);
        final long k1 = bytesToLong(keyBytes, 8);
        Arrays.fill(keyBytes, (byte) 0);

        initialState[3] ^= k1;
        initialState[2] ^= k0;
        initialState[1] ^= k1;
        initialState[0] ^= k0;

        long[] state = Arrays.copyOf(initialState, 4);

        int len = input.length - (input.length % 8);
        for (int offset = 0; offset < len; offset += 8) {
            long m = bytesToLong(input, offset);
            state[3] ^= m;

            // Compression rounds
            sipround(state);
            sipround(state);

            state[0] ^= m;
        }

        long b = lastBits(input);

        state[3] ^= b;
        // Last block compression rounds
        sipround(state);
        sipround(state);

        state[0] ^= b;
        state[2] ^= 0xff;
        // Finalization rounds
        sipround(state);
        sipround(state);
        sipround(state);
        sipround(state);

        b = state[0] ^ state[1] ^ state[2] ^ state[3];

        byte[] out = new byte[8];
        longToBytes(out, b);

        return out;
    }

    static long[] initialState() {
        return new long[] {
                0x736f6d6570736575L, // "somepseu"
                0x646f72616e646f6dL, // "dorandom"
                0x6c7967656e657261L, // "lygenera"
                0x7465646279746573L  // "tedbytes"
        };
    }

    @SuppressWarnings("fallthrough")
    static long lastBits(final byte[] input) {
        final int left = input.length & 7;
        final int len = input.length - (input.length % 8);
        long b = (long) input.length << 56;

        switch (left) {
        case 7:
            b |= ((long) input[len + 6]) << 48;
        case 6:
            b |= ((long) input[len + 5]) << 40;
        case 5:
            b |= ((long) input[len + 4]) << 32;
        case 4:
            b |= ((long) input[len + 3]) << 24;
        case 3:
            b |= ((long) input[len + 2]) << 16;
        case 2:
            b |= ((long) input[len + 1]) << 8;
        case 1:
            b |= ((long) input[len]);
            break;
        case 0:
            break;
        }
        return b;
    }

    /**
     * Implements a single round of the SipHash algorithm.
     *
     * @param state the internal state of the PRF. Must have exactly 4 elements.
     */
    static void sipround(long[] state) {
        long v0 = state[0], v1 = state[1], v2 = state[2], v3 = state[3];

        v0 += v1;
        v2 += v3;
        v1 = Long.rotateLeft(v1, 13);
        v3 = Long.rotateLeft(v3, 16);
        v1 ^= v0;
        v3 ^= v2;

        v0 = Long.rotateLeft(v0, 32);

        v2 += v1;
        v0 += v3;
        v1 = Long.rotateLeft(v1, 17);
        v3 = Long.rotateLeft(v3, 21);
        v1 ^= v2;
        v3 ^= v0;

        v2 = Long.rotateLeft(v2, 32);

        state[0] = v0;
        state[1] = v1;
        state[2] = v2;
        state[3] = v3;
    }

    static void longToBytes(byte[] p, long v) {
        assert p.length >= 8;
        p[0] = (byte) v;
        p[1] = (byte) (v >>> 8);
        p[2] = (byte) (v >>> 16);
        p[3] = (byte) (v >>> 24);
        p[4] = (byte) (v >>> 32);
        p[5] = (byte) (v >>> 40);
        p[6] = (byte) (v >>> 48);
        p[7] = (byte) (v >>> 56);
    }

    static long bytesToLong(byte[] p, int offset) {
        return l(p[offset]) | (l(p[offset + 1]) << 8) | (l(p[offset + 2]) << 16) | (l(p[offset + 3]) << 24)
                | (l(p[offset + 4]) << 32) | (l(p[offset + 5]) << 40) | (l(p[offset + 6]) << 48)
                | (l(p[offset + 7]) << 56);
    }

    private static long l(byte b) {
        return b & 0xffL;
    }
}