/*
 * Copyright 2019-2022 Neil Madden.
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

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

final class SHA512 {
    private static final String HASH_PROVIDER = "SUN";
    private static final String HMAC_PROVIDER = "SunJCE";
    private static final String HASH_ALGORITHM = "SHA-512";
    static final String MAC_ALGORITHM = "HmacSHA512";
    static final int HASH_LEN = 64;
    static final int HMAC_KEY_LEN = 32;
    static final int TAG_LEN = 32;

    static byte[] hash(byte[] data, int len) {
        if (len <= 0 || len > 64) {
            throw new IllegalArgumentException("len must be in range 1..64");
        }
        byte[] digest = null;
        try {
            MessageDigest sha512 = getDigest();
            digest = sha512.digest(data);
            return Arrays.copyOf(digest, len);
        } finally {
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }

    static byte[] hmac(Key key, byte[] data, int len) {
        if (len <= 0 || len > 64) {
            throw new IllegalArgumentException("len must be in range 1..64");
        }

        byte[] mac = null;
        try {
            Mac hmac = getMac();
            hmac.init(key);
            mac = hmac.doFinal(data);
            if (mac.length == len) {
                var tmp = mac;
                mac = null; // Avoid zeroing out if not copying
                return tmp;
            } else {
                return Arrays.copyOf(mac, len);
            }
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (mac != null) {
                Arrays.fill(mac, (byte) 0);
            }
        }
    }

    static MessageDigest getDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM, HASH_PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            try {
                return MessageDigest.getInstance(HASH_ALGORITHM);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException("JVM does not support SHA-512", ex);
            }
        }
    }

    static Mac getMac() {
        try {
            return Mac.getInstance(MAC_ALGORITHM, HMAC_PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            try {
                return Mac.getInstance(MAC_ALGORITHM);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException("JVM does not support HMAC-SHA-512", ex);
            }
        }
    }
}
