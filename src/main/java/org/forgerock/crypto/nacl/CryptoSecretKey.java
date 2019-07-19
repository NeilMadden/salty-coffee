/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import java.util.Arrays;

import javax.crypto.SecretKey;

final class CryptoSecretKey implements SecretKey {

    private final byte[] keyMaterial;
    private final String algorithm;

    CryptoSecretKey(byte[] keyMaterial, String algorithm) {
        this.keyMaterial = keyMaterial.clone();
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return keyMaterial.clone();
    }

    @Override
    public void destroy() {
        Arrays.fill(keyMaterial, (byte) 0);
    }

    @Override
    public boolean isDestroyed() {
        int x = 0;
        for (byte b : keyMaterial) {
            x |= b;
        }
        return x == 0;
    }
}
