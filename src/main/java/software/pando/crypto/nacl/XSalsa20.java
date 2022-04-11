/*
 * Copyright 2022 Neil Madden.
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

final class XSalsa20 {
    static final String ALGORITHM = "XSalsa20";
    static final int KEY_SIZE = XSalsa20Poly1305.KEY_SIZE;
    static final int NONCE_LEN = XSalsa20Poly1305.NONCE_LEN;

    static void encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        encrypt(key, nonce, 0, ByteSlice.of(plaintext), ByteSlice.of(plaintext));
    }

    static long encrypt(byte[] key, byte[] nonce, long blockCounter, ByteSlice plaintext, ByteSlice ciphertext) {
        assert key.length == KEY_SIZE;
        assert nonce.length == NONCE_LEN;

        byte[] subKey = HSalsa20.apply(key, nonce);
        try {
            byte[] subNonce = new byte[16];
            System.arraycopy(nonce, 16, subNonce, 0, 8);
            if (blockCounter != 0) {
                ByteBuffer.wrap(subNonce).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().put(1, blockCounter);
            }

            Salsa20.encrypt(subKey, subNonce, plaintext, ciphertext);
            return blockCounter + (plaintext.length + Salsa20.BLOCK_SIZE - 1) / Salsa20.BLOCK_SIZE;
        } finally {
            Arrays.fill(subKey, (byte) 0);
        }
    }

    static void decrypt(byte[] key, byte[] nonce, int blockCounter, ByteSlice ciphertext, ByteSlice plaintext) {
        encrypt(key, nonce, blockCounter, ciphertext, plaintext);
    }

    static void decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        encrypt(key, nonce, ciphertext);
    }
}
