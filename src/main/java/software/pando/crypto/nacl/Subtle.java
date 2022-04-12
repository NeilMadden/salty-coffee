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

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Cryptographic utilities and building blocks from which more complex requirements can be built, but which have
 * <strong>subtle security properties and dangerous edge-cases if misused.</strong> Unless you have significant
 * experience in the design of cryptographic protocols, you are strongly advised to only use the APIs in {@link Crypto}.
 * These utility methods are provided for advanced users and for compatibility with existing protocols and applications.
 */
public final class Subtle {
    /**
     * The size (in bytes) of keys used by {@link #streamXSalsa20Key(ByteSlice)}.
     */
    public static final int XSALSA20_KEY_SIZE = XSalsa20.KEY_SIZE;
    /**
     * The size (in bytes) of nonce expected by {@link #streamXSalsa20(SecretKey, byte[])}.
     */
    public static final int XSALSA20_NONCE_SIZE = XSalsa20.NONCE_LEN;

    /**
     * Performs a raw X25519 key agreement between the given private key (scalar) and the given public key (curve
     * point). The result is the raw output of the X25519 function, which hasn't been hashed or passed through a key
     * derivation function (KDF), so <strong>should not be directly used as a cryptographic key.</strong>
     *
     * @param privateKey the private key (scalar).
     * @param publicKey the public point to multiply by the scalar, as if through repeated point addition.
     * @return the u-coordinate output of the X25519 function applied to the given arguments.
     */
    public static byte[] scalarMultiplication(PrivateKey privateKey, PublicKey publicKey) {
        return CryptoBox.scalarMultiplication(privateKey, publicKey);
    }

    /**
     * Performs a raw X25519 key agreement between the given private key (scalar) and the given public key (curve
     * point). The result is the raw output of the X25519 function, which hasn't been hashed or passed through a key
     * derivation function (KDF), so <strong>should not be directly used as a cryptographic key.</strong>
     *
     * @param scalar the private scalar.
     * @param point the public point to multiply by the scalar, as if through repeated point addition.
     * @return the u-coordinate output of the X25519 function applied to the given arguments.
     */
    public static byte[] scalarMultiplication(byte[] scalar, byte[] point) {
        return CryptoBox.scalarMultiplication(CryptoBox.privateKey(scalar), CryptoBox.publicKey(point));
    }

    /**
     * Imports the given key bytes into a key object for use with {@link #streamXSalsa20(SecretKey)}. The byte slice is
     * wiped after the key is constructed.
     *
     * @param keyBytes the key bytes
     * @return the secret key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when no longer
     * required.
     */
    public static SecretKey streamXSalsa20Key(ByteSlice keyBytes) {
        if (keyBytes == null || keyBytes.length != XSalsa20.KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + XSalsa20.KEY_SIZE + " bytes");
        }
        try {
            return new CryptoSecretKey(keyBytes.toByteArray(), XSalsa20.ALGORITHM);
        } finally {
            keyBytes.wipe();
        }
    }

    /**
     * Imports the given key bytes into a key object for use with {@link #streamXSalsa20(SecretKey)}. The byte array is
     * wiped after the key is constructed, use {@code keyBytes.clone()} if you need to retain a copy.
     *
     * @param keyBytes the key bytes
     * @return the secret key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when no longer
     * required.
     */
    public static SecretKey streamXSalsa20Key(byte[] keyBytes) {
        return streamXSalsa20Key(ByteSlice.of(keyBytes));
    }

    /**
     * Generates a fresh random key for use with {@link #streamXSalsa20(SecretKey)}.
     *
     * @return the secret key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when no longer
     * required.
     */
    public static SecretKey streamXSalsa20KeyGen() {
        return streamXSalsa20Key(Bytes.secureRandom(XSalsa20.KEY_SIZE));
    }

    /**
     * Constructs and returns a low-level XSalsa20 stream cipher object that can be used to encrypt or decrypt an
     * effectively unlimited amount of data <em>without any integrity protection</em>.
     *
     * <p>XSalsa20 is an <em>unauthenticated</em> stream cipher, allowing an attacker to arbitrarily modify ciphertext
     * and potentially recover plaintext through chosen ciphertext attacks. It is highly recommended to use
     * {@link SecretBox} instead unless you really know what you are doing.
     *
     * <p>This version requires an explicit 24-byte nonce, which <strong>must be unique</strong> for each message
     * encrypted with the same key. Repeating a nonce results in almost total loss of security. It is recommended to use
     * {@link #streamXSalsa20(SecretKey)} for encryption to automatically generate a random nonce.
     *
     * @param key the key to use for encryption/decryption, created by {@link #streamXSalsa20Key(ByteSlice)}.
     * @param nonce the 24-byte unique nonce to use. This <strong>MUST</strong> be unique for each message encrypted
     *              with the same key. For decryption the nonce used during encryption must be provided.
     * @return the stream cipher object.
     */
    public static StreamCipher streamXSalsa20(SecretKey key, byte[] nonce) {
        if (!XSalsa20.ALGORITHM.equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid key");
        }
        var keyBytes = key.getEncoded();
        if (keyBytes.length != XSalsa20.KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key");
        }
        if (nonce == null || nonce.length != XSalsa20.NONCE_LEN) {
            throw new IllegalArgumentException("Invalid nonce");
        }
        return new XSalsa20StreamCipher(keyBytes, nonce, 0L);
    }

    /**
     * Constructs and returns a low-level XSalsa20 stream cipher object that can be used to encrypt or decrypt an
     * effectively unlimited amount of data <em>without any integrity protection</em>.
     *
     * <p>XSalsa20 is an <em>unauthenticated</em> stream cipher, allowing an attacker to arbitrarily modify ciphertext
     * and potentially recover plaintext through chosen ciphertext attacks. It is highly recommended to use
     * {@link SecretBox} instead unless you really know what you are doing.
     *
     * <p>This version generates a random 24-byte nonce and initializes the initial block counter to 0.
     *
     * @param key the key to use for encryption/decryption, created by {@link #streamXSalsa20Key(ByteSlice)}.
     * @return the stream cipher object.
     */
    public static StreamCipher streamXSalsa20(SecretKey key) {
        var nonce = Bytes.secureRandom(XSalsa20.NONCE_LEN);
        return streamXSalsa20(key, nonce);
    }

    private Subtle() {
        throw new UnsupportedOperationException();
    }

    /**
     * An <em>unauthenticated</em> low-level stream cipher object that can be used to encrypt or decrypt large amounts
     * of data. See {@link #streamXSalsa20(SecretKey)} for details and warnings.
     */
    public interface StreamCipher extends AutoCloseable {

        /**
         * Processes the given input slice, storing the output in the specified output slice. For encryption, the input
         * slice should be the plaintext to be encrypted and the ciphertext will be stored in the given output slice.
         * For decryption, the input should be the ciphertext and the plaintext will be stored in the output slice.
         * The output slice must be at least as large as the input slice. The two slices can refer to the same
         * underlying byte array to allow in-place encryption or decryption, but they should not be overlapping (but
         * not identical) ranges of the same bytes.
         *
         * @param input the input byte slice.
         * @param output the output byte slice.
         * @return an updated stream cipher object to process further inputs.
         */
        StreamCipher process(ByteSlice input, ByteSlice output);

        /**
         * Processes the given data in-place, overwriting the slice with the output. This is equivalent to calling
         * {@link #process(ByteSlice, ByteSlice)} with the same byte slice for both arguments.
         *
         * @param inputAndOutput the data to encrypt or decrypt in-place.
         * @return an updated stream cipher object to process further inputs.
         */
        default StreamCipher process(ByteSlice inputAndOutput) {
            return process(inputAndOutput, inputAndOutput);
        }

        /**
         * Provides access to the unique nonce that was used to initialize the stream cipher. If the nonce was generated
         * randomly (such as by {@link #streamXSalsa20(SecretKey)}, then it can be retrieved using this method. The
         * nonce should be stored alongside the encrypted message and passed to
         * {@link #streamXSalsa20(SecretKey, byte[])} for decryption. Typically the nonce is simply prepended to the
         * ciphertext. The nonce does not need to be kept secret, but if you are building an authenticated encryption
         * mode from this raw stream cipher then you should ensure that the nonce is included in the
         * {@linkplain Crypto#auth(SecretKey, byte[]) authenticated data}. The nonce returned by this method is fixed
         * size. For XSalsa20, the nonce is {@value XSALSA20_NONCE_SIZE}.
         *
         * @return a copy of the nonce.
         */
        byte[] nonce();

        /**
         * Indicates that all processing with this stream cipher object is now complete. Any key material will be
         * wiped from memory and further calls to {@link #process(ByteSlice, ByteSlice)} will result in an exception.
         * Wiping key material from memory is performed on a best-effort basis, because the JVM garbage collector may
         * have copied the data.
         */
        @Override
        void close();
    }

    private static class XSalsa20StreamCipher implements StreamCipher {
        private final byte[] key;
        private final byte[] nonce;
        private long blockCounter;
        private volatile boolean closed = false;

        XSalsa20StreamCipher(byte[] key, byte[] nonce, long blockCounter) {
            this.key = key;
            this.nonce = nonce;
            this.blockCounter = blockCounter;
        }

        @Override
        public StreamCipher process(ByteSlice input, ByteSlice output) {
            if (closed) {
                throw new IllegalStateException("Stream cipher has been closed");
            }
            blockCounter = XSalsa20.encrypt(key, nonce, blockCounter, input, output);
            return this;
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                Arrays.fill(key, (byte) 0);
            }
        }
    }
}
