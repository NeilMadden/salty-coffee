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

final class XSalsa20Poly1305 {
    static final String ALGORITHM = "XSalsa20-Poly1305";
    static final int KEY_SIZE = 32;
    static final int NONCE_LEN = 24;
    static final int TAG_OFFSET = 16;
    static final int TAG_SIZE = Poly1305.TAG_SIZE;

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == KEY_SIZE;
        assert nonce.length == NONCE_LEN;

        byte[] subKey = HSalsa20.apply(key, nonce);
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 0, 8);

        return Salsa20Poly1305.encrypt(subKey, subNonce, plaintext);
    }

    static byte[] decrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == 32;
        assert nonce.length == NONCE_LEN;

        byte[] subKey = HSalsa20.apply(key, nonce);
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 0, 8);

        return Salsa20Poly1305.decrypt(subKey, subNonce, plaintext);
    }
}
