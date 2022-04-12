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

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Iterator;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * The main interface to all cryptographic operations provided by this library.
 *
 * @see CryptoBox
 * @see SecretBox
 */
public final class Crypto {

    /**
     * Creates an authenticated and encrypted box using public key authenticated encryption. See {@link CryptoBox}
     * for the complete interface.
     *
     * @param privateKey the sender's private key.
     * @param publicKey the recipient's public key.
     * @param plaintext the message to encrypt and authenticate.
     * @return the encrypted and authenticated box.
     */
    public static CryptoBox box(PrivateKey privateKey, PublicKey publicKey, byte[] plaintext) {
        return CryptoBox.encrypt(privateKey, publicKey, plaintext);
    }

    /**
     * Creates an authenticated and encrypted box using secret key authenticated encryption. See {@link SecretBox}
     * for the complete interface.
     *
     * @param key the shared secret key.
     * @param plaintext the message to encrypt and authenticate.
     * @return the encrypted and authenticated box.
     */
    public static SecretBox box(SecretKey key, byte[] plaintext) {
        return SecretBox.encrypt(key, plaintext);
    }

    /**
     * Hashes the given data with a collision-resistant hash function. The algorithm is SHA-512.
     *
     * @param data the data to hash.
     * @return the 64-byte computed hash.
     */
    public static byte[] hash(byte[] data) {
        return SHA512.hash(data, SHA512.HASH_LEN);
    }

    /**
     * Generates a secret key for use with the {@link #auth(SecretKey, byte[])} method to authenticate messages. Use
     * {@link SecretKey#destroy()} to wipe the key contents when you are finished with it.
     *
     * @return the generated secret key.
     */
    public static SecretKey authKeyGen() {
        return new CryptoSecretKey(Bytes.secureRandom(SHA512.HMAC_KEY_LEN), SHA512.MAC_ALGORITHM);
    }

    /**
     * Converts the given bytes into a secret key for use with {@link #auth(SecretKey, byte[])}.
     *
     * @param keyBytes the key bytes.
     * @return the secret key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when no longer
     * required.
     */
    public static SecretKey authKey(byte[] keyBytes) {
        if (keyBytes.length != SHA512.HMAC_KEY_LEN) {
            throw new IllegalArgumentException("invalid key");
        }
        return new CryptoSecretKey(keyBytes, SHA512.MAC_ALGORITHM);
    }

    /**
     * Converts the given bytes into a secret key for use with {@link #auth(SecretKey, byte[])}.
     *
     * @param keyBytes the key bytes.
     * @return the secret key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when no longer
     * required.
     */
    public static SecretKey authKey(ByteSlice keyBytes) {
        return authKey(keyBytes.toByteArray());
    }

    /**
     * Authenticates the given message and returns a 32-byte authentication tag that can be used with
     * {@link #authVerify(SecretKey, byte[], byte[])} to ensure the message has not been forged or tampered with.
     * This uses HMAC-SHA512-256 (the first 256 bits of the output of HMAC-SHA512).
     *
     * @param authKey the authentication key. See {@link #authKeyGen()}.
     * @param message the message to be authenticated.
     * @return the 32-byte authentication tag.
     */
    public static byte[] auth(SecretKey authKey, byte[] message) {
        return SHA512.hmac(authKey, message, SHA512.TAG_LEN);
    }

    /**
     * Verifies that the given message is valid according to the supplied authentication tag. A fresh tag is computed
     * using {@link #auth(SecretKey, byte[])} and then compared against the supplied tag using a constant-time
     * equality test.
     *
     * @param authKey the authentication key.
     * @param message the message to authenticate.
     * @param tag the supplied authentication tag.
     * @return {@code true} if the tag is valid for this message, otherwise {@code false}.
     */
    public static boolean authVerify(SecretKey authKey, byte[] message, byte[] tag) {
        byte[] computed = auth(authKey, message);
        try {
            return Bytes.equal(computed, tag);
        } finally {
            Arrays.fill(computed, (byte) 0);
        }
    }

    /**
     * Authenticates one or more message blocks and returns a 32-byte authentication tag that can be used with
     * {@link #authVerifyMulti(SecretKey, Iterable, byte[])} to ensure the blocks have not been forged or tampered with.
     * Each block is individually authenticated, independent of any other blocks. For example, the two blocks
     * {@code ["foo", "bar"]} will produce a different authentication tag to the two blocks {@code ["fo", "obar"]}, and
     * to the two blocks {@code ["bar", "foo"]}, or any other combination. Only the exact same sequence of blocks, in
     * the same order, will produce the same authentication tag for a given key.
     *
     * <p>The algorithm used is as follows:
     * <ol>
     *     <li>First, two 256-bit sub-keys, {@code macKey} and {@code finKey}, are derived from the input key using
     *     {@link #kdfDeriveFromKey(SecretKey, byte[], int)} with the ASCII bytes of the string
     *     {@code "AuthMulti-HMAC-SHA-512-256"} as the context.</li>
     *     <li>The blocks are then processed in a <a href="https://cseweb.ucsd.edu/~mihir/papers/cascade.pdf"
     *     ><em>cascade</em></a> construction using the macKey, as in the following
     *     pseudocode:
     *     <pre>{@code
     *         require blocks.size() > 0
     *         var tag = null
     *         for block in blocks:
     *             tag = auth(macKey, block)
     *             macKey = authKey(tag)
     *         end
     *     }</pre>
     *     </li>
     *     <li>The tag is then finalized by applying {@code tag = auth(finKey, tag)} using the separate finalization
     *     key, to prevent <a href="https://en.wikipedia.org/wiki/Length_extension_attack">length extension
     *     attacks</a>.</li>
     * </ol>
     *
     * <p><strong>Warning:</strong> a given key should either be used for {@link #auth(SecretKey, byte[])} <em>or</em>
     * for this method, never for both.
     *
     * <p>Note: if the {@code authKey} argument is stored in a Hardware Security Module or other secure hardware
     * solution, be aware that this method derives key-equivalent material that is kept in-memory, outside of the
     * protection of the secure hardware. If hardware security protection is essential to your use-case, then consider
     * using an alternative method, such as combining the data blocks into some unambiguous encoding and passing the
     * entire encoded data as one argument to {@link #auth(SecretKey, byte[])} instead.
     *
     * <p>The implementation is guaranteed to call {@link Iterable#iterator()} at most once on the argument.
     *
     * @param authKey the authentication key. See {@link #authKeyGen()}.
     * @param blocks the blocks of data to be authenticated.
     * @return the 32-byte authentication tag.
     * @throws IllegalArgumentException if either input argument is {@code null} or there is not at least one data
     * block provided.
     */
    public static byte[] authMulti(SecretKey authKey, Iterable<byte[]> blocks) {
        Iterator<byte[]> iterator;
        if (blocks == null || !(iterator = blocks.iterator()).hasNext()) {
            throw new IllegalArgumentException("Must supply at least one data block to authenticate");
        }
        var context = "AuthMulti-HMAC-SHA-512-256".getBytes(US_ASCII);
        var subKeys = kdfDeriveFromKey(authKey, context, 64);
        var macKey = (CryptoSecretKey) authKey(ByteSlice.ofRange(subKeys, 0, 32));
        var finKey = (CryptoSecretKey) authKey(ByteSlice.ofRange(subKeys, 32, 64));

        try {
            byte[] tag = new byte[0];
            while (iterator.hasNext()) {
                var block = iterator.next();
                if (block == null) {
                    throw new IllegalArgumentException("Null data block");
                }
                Arrays.fill(tag, (byte) 0);
                tag = auth(macKey, block);
                macKey = (CryptoSecretKey) authKey(tag);
            }
            tag = auth(finKey, tag);
            return tag;
        } finally {
            macKey.destroy();
            finKey.destroy();
        }
    }

    /**
     * Verifies an authenticate tag previously computed over a list of data blocks by
     * {@link #authMulti(SecretKey, Iterable)}. If any block has been altered, or a block added, removed, or rearranged
     * then the authentication will fail (returning {@code false}).
     *
     * @param authKey the authentication key. See {@link #authKeyGen()}.
     * @param blocks the blocks of data to be authenticated.
     * @param expectedTag the authentication tag previously computed by a call to
     * {@link #authMulti(SecretKey, Iterable)}.
     * @return {@code true} if the computed authentication tag matches the expected one (with the comparison performed
     * in constant time), otherwise {@code false}.
     * @throws IllegalArgumentException if any of the arguments is {@code null}, or if there is not at least one
     * block in the blocks iterable.
     */
    public static boolean authVerifyMulti(SecretKey authKey, Iterable<byte[]> blocks, byte[] expectedTag) {
        if (expectedTag == null) {
            throw new IllegalArgumentException("Invalid tag");
        }
        byte[] computedTag = authMulti(authKey, blocks);
        try {
            return Bytes.equal(computedTag, expectedTag);
        } finally {
            Arrays.fill(computedTag, (byte) 0);
        }
    }

    /**
     * Generates a random signing key pair for use with {@link #sign(PrivateKey, byte[])} and
     * {@link #signVerify(PublicKey, byte[], byte[])}. Use {@link PrivateKey#destroy()} when you are finished with
     * the private key to destroy the key material.
     *
     * @return a fresh signing key pair.
     */
    public static KeyPair signingKeyPair() {
        return seedSigningKeyPair(Bytes.secureRandom(Ed25519.SECRET_KEY_LEN));
    }

    /**
     * Generates a signing key pair deterministically from the given seed. The same seed can be used to recreate the
     * same key pair on any machine.
     * <p>
     * <strong>WARNING</strong>: The seed is equivalent to a private key and should be generated and stored securely.
     *
     * @param seed the 32-byte random seed.
     * @return the generated key pair.
     */
    public static KeyPair seedSigningKeyPair(byte[] seed) {
        if (seed.length != Ed25519.SECRET_KEY_LEN) {
            throw new IllegalArgumentException("seed must be exactly " + Ed25519.SECRET_KEY_LEN + " bytes");
        }
        Ed25519.PrivateKey privateKey = new Ed25519.PrivateKey(seed);
        return new KeyPair(new Ed25519.PublicKey(privateKey.getPublicKey()), privateKey);
    }

    /**
     * Converts a raw Ed25519 private key scalar value into a signing private key.
     *
     * @param bytes the 32-byte raw Ed25519 private key.
     * @return the private key object.
     */
    public static PrivateKey signingPrivateKey(byte[] bytes) {
        return new Ed25519.PrivateKey(bytes);
    }

    /**
     * Converts a raw Ed25519 public key into a signing public key.
     *
     * @param bytes the bytes of the Ed25519 public key.
     * @return the public key object.
     */
    public static PublicKey signingPublicKey(byte[] bytes) {
        return new Ed25519.PublicKey(bytes);
    }

    /**
     * Signs the given message with the given private key.
     *
     * @param privateKey the signing private key.
     * @param data the data to sign.
     * @return the signature.
     * @throws IllegalArgumentException if the private key was not produced by {@link #signingKeyPair()} or
     * {@link #signingPrivateKey(byte[])}.
     */
    public static byte[] sign(PrivateKey privateKey, byte[] data) {
        if (!(privateKey instanceof Ed25519.PrivateKey)) {
            throw new IllegalArgumentException("invalid Ed25519 private key");
        }
        byte[] hashedPrivateKey = ((Ed25519.PrivateKey) privateKey).getHashedScalar();
        byte[] publicKey = ((Ed25519.PrivateKey) privateKey).getPublicKey();
        return Ed25519.sign(data, publicKey, hashedPrivateKey);
    }

    /**
     * Verifies a signature produced by {@link #sign(PrivateKey, byte[])}.
     *
     * @param publicKey the public key.
     * @param data the data to verify.
     * @param signature the signature.
     * @return whether the signature is valid.
     * @throws IllegalArgumentException if the public key was not produced by {@link #signingKeyPair()} or
     * {@link #signingPublicKey(byte[])}.
     */
    public static boolean signVerify(PublicKey publicKey, byte[] data, byte[] signature) {
        if (!(publicKey instanceof Ed25519.PublicKey)) {
            throw new IllegalArgumentException("invalid Ed25519 public key");
        }
        return Ed25519.verify(data, signature, ((Ed25519.PublicKey) publicKey).getKeyBytes());
    }

    /**
     * Generates a fresh random secret key that can be used to generate one or more other keys via
     * {@link #kdfDeriveFromKey(SecretKey, byte[], int)}.
     *
     * @return a fresh random HKDF root key. The returned key can be {@linkplain Destroyable#destroy() destroyed} when
     * no longer required.
     */
    public static SecretKey kdfKeyGen() {
        return authKeyGen();
    }

    /**
     * Derives one or more sub-keys from a single high-quality root key. Up to 16,320 bytes of key material can be
     * derived using this method. This method is <em>not suitable</em> for deriving keys from a password or other
     * low-entropy input.
     *
     * <p>If deriving multiple keys from the same input key material it is recommended to either derive all the required
     * key material in one call, or else to ensure that the context argument is different on each call. Otherwise,
     * identical keys will be generated.
     *
     * <p>If the rootKey is stored in a Hardware Security Module or other secure cryptographic module, be aware that the
     * output key material is exposed in-memory, outside of the confines of the secure processor. In this case, it is
     * recommended that the context argument be as specific as possible, ideally including a per-invocation random
     * component (such as a message ID) so that compromise of the output key material doesn't allow an attacker to
     * bypass the HSM entirely.
     *
     * <p><strong>Warning:</strong> the root key should only be used to derive other keys, and not also used directly
     * for {@link #auth(SecretKey, byte[])} or for other algorithms. Doing so may allow an attacker to recover key
     * material by crafting carefully chosen messages for you to authenticate.
     *
     * <p>The current implementation uses <a href="https://www.rfc-editor.org/rfc/rfc5869">HKDF</a>
     * instantiated with HMAC-SHA-512.
     *
     * @param rootKey the high entropy root key to derive further sub-keys from.
     * @param context the context in which the key is being used. This context argument should typically encode
     *                protocol or application identifiers, identifiers of parties involved in a cryptographic
     *                transaction, and public key material or certificates of those parties.
     * @param outputKeySizeBytes the total number of bytes of output, up to 16,320 bytes.
     * @return the requested key material derived from the root key and context.
     */
    public static byte[] kdfDeriveFromKey(SecretKey rootKey, byte[] context, int outputKeySizeBytes) {
        return HKDF.HKDF_HMAC_SHA512.expand(rootKey, context, outputKeySizeBytes);
    }

    /**
     * Derives one or more sub-keys from some high-entropy, but not necessarily uniformly random, input key material.
     * Up to 16,320 bytes of key material can be derived using this method. This method is <em>not suitable</em> for
     * deriving keys from a password or other low-entropy input.
     *
     * <p>The current implementation uses <a href="https://www.rfc-editor.org/rfc/rfc5869">HKDF</a>
     * instantiated with HMAC-SHA-512.
     *
     * @param inputKeyMaterial the high entropy key material to derive further sub-keys from, such as the output from
     *               {@link Subtle#scalarMultiplication(PrivateKey, PublicKey)}.
     * @param salt an optional uniformly random salt value to improve entropy extraction from the input key material.
     *            This value should ideally be of high entropy, and should never be attacker-controlled. The value
     *             can be fixed and public and even a low-entropy value provides some value in terms of domain
     *             separation.
     * @param context the context in which the key is being used. This context argument should typically encode
     *                protocol or application identifiers, identifiers of parties involved in a cryptographic
     *                transaction, and public key material or certificates of those parties.
     * @param outputKeySizeBytes the total number of bytes of output, up to 16,320 bytes.
     * @return the requested key material derived from the root key and context.
     */
    public static byte[] kdfDeriveFromInputKeyMaterial(byte[] salt, byte[] inputKeyMaterial, byte[] context,
            int outputKeySizeBytes) {
        try (var prk = HKDF.HKDF_HMAC_SHA512.extract(salt, inputKeyMaterial)) {
            return kdfDeriveFromKey(prk, context, outputKeySizeBytes);
        }
    }

    private Crypto() {
        throw new UnsupportedOperationException();
    }
}
