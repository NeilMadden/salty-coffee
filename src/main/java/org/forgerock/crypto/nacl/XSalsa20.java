/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

final class XSalsa20 {

    static void encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == 32;
        assert nonce.length == 24;

        byte[] subkey = HSalsa20.apply(key, nonce);
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 4, 8);

        Salsa20.encrypt(subkey, subNonce, plaintext);
    }

    static void decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        encrypt(key, nonce, ciphertext);
    }

}
