/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import java.util.Arrays;

final class Salsa20Poly1305 {

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        assert key.length == 32;
        assert nonce.length >= 8;

        byte[] ciphertext = new byte[plaintext.length + 32];
        System.arraycopy(plaintext, 0, ciphertext, 32, plaintext.length);

        Salsa20.encrypt(key, nonce, ciphertext);

        byte[] poly1305Key = Arrays.copyOf(ciphertext, 32);

        byte[] tag = Poly1305.compute(poly1305Key, ciphertext, 32, ciphertext.length);
        assert tag.length == Poly1305.TAG_SIZE;
        Arrays.fill(poly1305Key, (byte) 0);

        Arrays.fill(ciphertext, 0, 16, (byte) 0);
        System.arraycopy(tag, 0, ciphertext, 16, tag.length);
        Arrays.fill(tag, (byte) 0);

        return ciphertext;
    }

    static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        assert key.length == 32;
        assert nonce.length >= 8;
        assert ciphertext.length >= 32;

        byte[] providedTag = Arrays.copyOfRange(ciphertext, 16, 32);

        byte[] firstBlock = new byte[64];
        Salsa20.encrypt(key, nonce, firstBlock);
        byte[] poly1305Key = Arrays.copyOf(firstBlock, 32);
        Arrays.fill(firstBlock, (byte) 0);
        Arrays.fill(ciphertext, 0, 32, (byte) 0);

        byte[] computedTag = Poly1305.compute(poly1305Key, ciphertext, 32, ciphertext.length);
        Arrays.fill(poly1305Key, (byte) 0);

        if (!Bytes.equal(providedTag, computedTag)) {
            Arrays.fill(computedTag, (byte) 0);
            throw new IllegalArgumentException("invalid authentication tag");
        }

        Salsa20.decrypt(key, nonce, ciphertext);
        return Arrays.copyOfRange(ciphertext, 32, ciphertext.length);
    }


}
