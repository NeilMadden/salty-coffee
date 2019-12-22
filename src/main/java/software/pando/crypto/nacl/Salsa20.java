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

package software.pando.crypto.nacl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

final class Salsa20 {
    private static final int STATE_LEN = 16;

    static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[b] ^= Integer.rotateLeft(state[a] + state[d],  7);
        state[c] ^= Integer.rotateLeft(state[b] + state[a],  9);
        state[d] ^= Integer.rotateLeft(state[c] + state[b], 13);
        state[a] ^= Integer.rotateLeft(state[d] + state[c], 18);
    }

    static void rounds(int[] state) {
        assert state.length == STATE_LEN;

        for (int i = 0; i < 10; ++i) {
            quarterRound(state, 0,   4,  8, 12);
            quarterRound(state, 5,   9, 13,  1);
            quarterRound(state, 10, 14,  2,  6);
            quarterRound(state, 15,  3,  7, 11);
            quarterRound(state, 0,   1,  2,  3);
            quarterRound(state, 5,   6,  7,  4);
            quarterRound(state, 10, 11,  8,  9);
            quarterRound(state, 15, 12, 13, 14);
        }
    }

    static int[] blockFunction(int[] state) {
        assert state.length == STATE_LEN;

        int[] x = Arrays.copyOf(state, state.length);
        rounds(x);
        for (int i = 0; i < STATE_LEN; ++i) {
            x[i] += state[i];
        }
        return x;
    }

    private static byte[] bytes(int[] block) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(block.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.asIntBuffer().put(block);
        return byteBuffer.array();
    }

    static void encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == 32;
        assert nonce.length >= 8;

        if (nonce.length < 16) {
            byte[] newNonce = new byte[16];
            System.arraycopy(nonce, 0, newNonce, 0, nonce.length);
            nonce = newNonce;
        }

        int[] state = initialState(key, nonce);

        int numBlocks = (plaintext.length + 63) >>> 6;
        for (int block = 0; block < numBlocks; ++block) {
            state[8] = block;

            byte[] keystream = bytes(blockFunction(state));

            int start = block * 64;
            int end = Math.min(start + 64, plaintext.length);
            for (int i = start; i < end; ++i) {
                plaintext[i] ^= keystream[i - start];
            }
            Arrays.fill(keystream, (byte) 0);
        }
    }

    static void decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        encrypt(key, nonce, ciphertext);
    }

    static int[] initialState(byte[] key, byte[] nonce) {
        assert key.length == 32;
        assert nonce.length >= 16;

        int[] state = new int[STATE_LEN];

        // Magic numbers
        state[0] = 0x61707865;
        state[5] = 0x3320646e;
        state[10] = 0x79622d32;
        state[15] = 0x6b206574;

        // Key bytes
        ByteBuffer buf = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        state[1] = buf.getInt();
        state[2] = buf.getInt();
        state[3] = buf.getInt();
        state[4] = buf.getInt();
        state[11] = buf.getInt();
        state[12] = buf.getInt();
        state[13] = buf.getInt();
        state[14] = buf.getInt();

        // Block counter and nonce
        buf = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN);
        state[6] = buf.getInt();
        state[7] = buf.getInt();
        state[8] = buf.getInt();
        state[9] = buf.getInt();

        return state;
    }

}
