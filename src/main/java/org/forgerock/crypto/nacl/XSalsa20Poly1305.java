/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

final class XSalsa20Poly1305 {
    static final int NONCE_LEN = 24;
    static final int TAG_OFFSET = 16;
    static final int TAG_SIZE = Poly1305.TAG_SIZE;

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == 32;
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
