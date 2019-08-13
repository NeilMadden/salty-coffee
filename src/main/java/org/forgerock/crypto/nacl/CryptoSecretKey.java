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
