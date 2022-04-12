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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implementation of the
 * <a href="https://www.rfc-editor.org/rfc/rfc5869">HMAC-based Extract-and-Expand Key Derivation function (HKDF).</a>
 */
final class HKDF {
    static final HKDF HKDF_HMAC_SHA512 = new HKDF(SHA512.MAC_ALGORITHM);

    private final int saltLenBytes;
    private final int tagLenBytes;
    private final String hmacAlgorithm;

    HKDF(String hmacAlgorithm) {
        try {
            this.hmacAlgorithm = Objects.requireNonNull(hmacAlgorithm);
            var mac = Mac.getInstance(hmacAlgorithm);
            this.saltLenBytes = mac.getMacLength();
            this.tagLenBytes = mac.getMacLength();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Extracts a pseudorandom key (PRK) from some input key material, which is high entropy but potentially not a
     * uniform random bit string.
     *
     * @param salt an optional random salt parameter to improve the entropy extraction process, or at least provide
     *             domain separation when the same input key material is used for different applications. Ideally
     *             this should be a uniform random bit string, but it can be public and fixed for a given application.
     * @param inputKeyMaterial the input key material.
     * @return a high quality pseudorandom key that is suitable for use with {@link #expand(SecretKey, byte[], int)}
     * to derive further keys.
     */
    CryptoSecretKey extract(byte[] salt, byte[] inputKeyMaterial) {
        if (salt == null || salt.length == 0) {
            salt = new byte[saltLenBytes];
        }
        try (var saltAsKey = hmacKey(salt)) {
            return hmacKey(hmac(saltAsKey, inputKeyMaterial));
        }
    }

    /**
     * Expands a single high-quality key into a pseudorandom key stream suitable for use as cryptographic keys. The
     * derived key material is bound to the given context, ensuring that keys derived for different contexts are
     * independent of each other.
     *
     * @param prk the single key to derive multiple keys from.
     * @param context the context in which the key is being used. This context argument should typically encode
     *                protocol or application identifiers, identifiers of parties involved in a cryptographic
     *                transaction, and public key material or certificates of those parties.
     * @param outputKeySizeBytes the size of key material to generate, in bytes. This has a maximum of 8,160 bytes.
     * @return the derived output key material.
     */
    byte[] expand(SecretKey prk, byte[] context, int outputKeySizeBytes) {
        if (outputKeySizeBytes <= 0 || outputKeySizeBytes > 255 * tagLenBytes) {
            throw new IllegalArgumentException("Output size must be >= 1 and <= " + 255 * tagLenBytes);
        }
        byte[] last = new byte[0];
        byte[] counter = new byte[1];
        byte[] output = new byte[outputKeySizeBytes];
        for (int i = 0; i < outputKeySizeBytes; i += tagLenBytes) {
            counter[0]++;
            last = hmac(prk, Bytes.concat(last, context, counter));
            System.arraycopy(last, 0, output, i, Math.min(outputKeySizeBytes - i, tagLenBytes));
        }
        return output;
    }

    private byte[] hmac(SecretKey key, byte[] data) {
        try {
            var mac = Mac.getInstance(hmacAlgorithm);
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private CryptoSecretKey hmacKey(byte[] keyMaterial) {
        try {
            return new CryptoSecretKey(keyMaterial, hmacAlgorithm);
        } finally {
            Arrays.fill(keyMaterial, (byte) 0);
        }
    }
}
