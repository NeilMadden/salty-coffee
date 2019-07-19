/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

final class SHA512 {
    static byte[] hash(byte[] data, int len) {
        if (len <= 0 || len > 64) {
            throw new IllegalArgumentException("len must be in range 1..64");
        }
        byte[] digest = null;
        try {
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            digest = sha512.digest(data);
            return Arrays.copyOf(digest, len);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } finally {
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }
}
