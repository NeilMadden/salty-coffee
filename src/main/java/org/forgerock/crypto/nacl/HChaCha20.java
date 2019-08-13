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

final class HChaCha20 {

    private static final int[] OUTPUT_INDICES = { 0, 1, 2, 3, 12, 13, 14, 15 };

    private static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a],  8);
        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c],  7);
    }

    private static int[] initialState(byte[] key, byte[] nonce) {
        assert key.length == 32;
        assert nonce.length >= 16;

        int[] state = new int[16];

        // Magic numbers
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        ByteBuffer buf = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 4; i < 12; ++i) {
            state[i] = buf.getInt();
        }

        buf = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 12; i < 16; ++i) {
            state[i] = buf.getInt();
        }

        return state;
    }

    static byte[] apply(byte[] key, byte[] nonce) {
        int[] state = initialState(key, nonce);

        for (int i = 0; i < 10; ++i) {
            quarterRound(state, 0, 4,  8, 12);
            quarterRound(state, 1, 5,  9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7,  8, 13);
            quarterRound(state, 3, 4,  9, 14);
        }

        ByteBuffer buffer = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        for (int i : OUTPUT_INDICES) {
            buffer.putInt(state[i]);
        }

        return buffer.array();
    }
}
