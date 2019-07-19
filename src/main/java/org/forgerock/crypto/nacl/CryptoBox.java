/*
 * Copyright 2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyAgreement;

/**
 * Implements the <a href="https://nacl.cr.yp.to/box.html">NaCl crypto_box</a> function. A crypto box provides public
 * key authenticated encryption.
 * <h2>Key-pair generation</h2>
 * <pre>{@code
 * KeyPair keyPair = CryptoBox.keyPair();
 * }</pre>
 * Generates a random public/private key-pair. You can use {@link #privateKey(byte[])} and {@link #publicKey(byte[])} to
 * reconstruct private or public keys from bytes.
 *
 * <h2>Encrypting a message</h2>
 * <pre>{@code
 * PrivateKey from = ...;
 * PublicKey to = ...;
 * String msg = ...; // or byte[] msg
 * CryptoBox box = CryptoBox.encrypt(from, to, msg);
 * }</pre>
 * This will derive a key that is unique to the given from/to pair and uses it to encrypt and authenticate the given
 * message. A unique random nonce will be generated on each call, or you can use
 * {@link #encrypt(PrivateKey, PublicKey, byte[], byte[])} to specify the 24-byte nonce manually but <strong>it must
 * be unique for every call with the same participants</strong>. Reusing a nonce undermines the security
 * guarantees. Note that this uniqueness requirement applies also when the to and from roles are swapped. It is
 * recommended to let the library generate random nonces for you.
 * <p>
 * The generated nonce can ba accessed via {@link #getNonce()}. Traditionally the NaCl library prepends the
 * authentication tag to the ciphertext, and you can retrieve this representation via {@link #getCiphertextWithTag()}.
 * You can also obtain these components separately via {@link #getTag()} and {@link #getCiphertextWithoutTag()}.
 * <p>
 * A crypto box can be reconstructed either from the combined ciphertext with tag using
 * {@link #fromCombined(byte[], byte[])} or from the separate ("detached") ciphertext and tag components using
 * {@link #fromDetached(byte[], byte[], byte[])}.
 * <p>
 * Alternatively you can use the {@link #writeTo(OutputStream)} and {@link #readFrom(InputStream)} methods to
 * serialize the cryptobox to/from a stream with the nonce and tag.
 *
 * <h2>Decrypting</h2>
 * <pre>{@code
 * CryptoBox box = CryptoBox.readFrom(in);
 * PrivateKey ourPrivateKey = ...;
 * PublicKey sender = ...;
 *
 * String msg = box.decryptToString(ourPrivateKey, sender);
 * }</pre>
 * You can use either the {@link #decrypt(PrivateKey, PublicKey)} or {@link #decryptToString(PrivateKey, PublicKey)}
 * methods to decrypt the box. The latter assumes that the message is in UTF-8 encoding.
 *
 * <h2>Algorithms</h2>
 * CryptoBox uses the X25519 elliptic curve Diffie-Hellman key agreement function together with HSalsa20 to derive a
 * shared key between the sender and recipient. It then uses the XSalsa20-Poly1305 authenticated encryption algorithm
 * to encrypt messages.
 */
public final class CryptoBox implements AutoCloseable {
    private static final String KEY_AGREEMENT_ALGORITHM = "X25519";
    private static final AlgorithmParameterSpec X25519_PARAMS = new NamedParameterSpec(KEY_AGREEMENT_ALGORITHM);

    private static final byte[] ZERO = new byte[16];

    /**
     * Generates an X25519 key pair.
     *
     * @return the generated key pair.
     */
    public static KeyPair keyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyPairGenerator.initialize(X25519_PARAMS);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Unable to generate key pair", e);
        }
    }

    public static KeyPair seedKeyPair(byte[] seed) {
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException("invalid seed: must be exactly 32 bytes");
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyPairGenerator.initialize(X25519_PARAMS, seedSecureRandom(seed));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Unable to generate key pair", e);
        }
    }

    private static SecureRandom seedSecureRandom(byte[] seed) {
        return new SecureRandom(new SeedSecureRandom(seed), null) {};
    }

    /**
     * Reconstructs an X25519 public key from the little-endian bytes of the u-coordinate of the public key point.
     *
     * @param publicKeyBytes the little-endian bytes of the public key u-coordinate.
     * @return the public key.
     */
    public static PublicKey publicKey(byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_ALGORITHM);
            BigInteger u = new BigInteger(Bytes.reverse(publicKeyBytes));
            return keyFactory.generatePublic(new XECPublicKeySpec(X25519_PARAMS, u));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Unable to generate public key", e);
        }
    }

    /**
     * Reconstructs an X25519 private key from the given scalar value bytes.
     *
     * @param privateKeyBytes the X25519 scalar value.
     * @return the private key.
     */
    public static PrivateKey privateKey(byte[] privateKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_ALGORITHM);
            return keyFactory.generatePrivate(new XECPrivateKeySpec(X25519_PARAMS, privateKeyBytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Unable to generate private key", e);
        }
    }

    /**
     * Encrypts and authenticates the given plaintext message so that it can only be read by the given recipient and
     * could only have been generated by the given sender. This version allows the caller to specify a nonce.
     * <strong>The nonce must be unique for every invocation of this function with the same participants.</strong> It
     * is recommended to use {@link #encrypt(PrivateKey, PublicKey, byte[])} instead.
     *
     * @param ourPrivateKey the sender's private key.
     * @param theirPublicKey the recipient's public key.
     * @param nonce the unique nonce. Must be exactly 24 bytes long.
     * @param plaintext the plaintext message to encrypt.
     * @return the encrypted and authenticated ciphertext.
     */
    public static CryptoBox encrypt(PrivateKey ourPrivateKey, PublicKey theirPublicKey, byte[] nonce,
            byte[] plaintext) {
        if (nonce.length != XSalsa20Poly1305.NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be 24 bytes");
        }
        byte[] key = agreeKey(ourPrivateKey, theirPublicKey);
        try {
            return new CryptoBox(nonce, XSalsa20Poly1305.encrypt(key, nonce, plaintext));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Encrypts and authenticates the given plaintext message so that it can only be read by the given recipient and
     * could only have been generated by the given sender. A random 24-byte nonce will be generated for each message
     * and can be retrieved using {@link #getNonce()}.
     *
     * @param ourPrivateKey the sender's private key.
     * @param theirPublicKey the recipient's public key.
     * @param plaintext the plaintext message to encrypt.
     * @return the encrypted and authenticated ciphertext.
     */
    public static CryptoBox encrypt(PrivateKey ourPrivateKey, PublicKey theirPublicKey, byte[] plaintext) {
        byte[] nonce = Bytes.secureRandom(XSalsa20Poly1305.NONCE_LEN);
        return encrypt(ourPrivateKey, theirPublicKey, nonce, plaintext);
    }

    /**
     * Encrypts and authenticates the given plaintext message so that it can only be read by the given recipient and
     * could only have been generated by the given sender. A random 24-byte nonce will be generated for each message
     * and can be retrieved using {@link #getNonce()}. The plaintext will be converted to UTF-8 bytes before encryption.
     *
     * @param ourPrivateKey the sender's private key.
     * @param theirPublicKey the recipient's public key.
     * @param plaintext the plaintext message to encrypt.
     * @return the encrypted and authenticated ciphertext.
     */
    public static CryptoBox encrypt(PrivateKey ourPrivateKey, PublicKey theirPublicKey, String plaintext) {
        return encrypt(ourPrivateKey, theirPublicKey, plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Derives a shared secret key that can be used to encrypt messages between the two parties. The key can be used
     * with {@link SecretBox#encrypt(Key, byte[])} to encrypt multiple independent messages to the same recipient.
     * This is equivalent to the NaCl {@code crypto_box_beforenm} function. The {@code crypto_box_afternm} function
     * of NaCl is identical to {@code crypto_secretbox}, so we do not implement it.
     *
     * @param ourPrivateKey the sender's private key.
     * @param theirPublicKey the recipient's public key.
     * @return the derived secret key.
     */
    public static Key agree(PrivateKey ourPrivateKey, PublicKey theirPublicKey) {
        return SecretBox.key(agreeKey(ourPrivateKey, theirPublicKey));
    }

    static byte[] agreeKey(PrivateKey ourPrivateKey, PublicKey theirPublicKey) {
        byte[] sharedSecret = null;
        try {
            KeyAgreement x25519 = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
            x25519.init(ourPrivateKey);
            x25519.doPhase(theirPublicKey, true);
            sharedSecret = x25519.generateSecret();

            return HSalsa20.apply(sharedSecret, ZERO);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("X25519 not supported", e);
        } finally {
            if (sharedSecret != null) {
                Arrays.fill(sharedSecret, (byte) 0);
            }
        }
    }

    private final byte[] nonce;
    private final byte[] ciphertext;

    private CryptoBox(byte[] nonce, byte[] ciphertext) {
        if (nonce.length != XSalsa20Poly1305.NONCE_LEN) {
            throw new IllegalArgumentException("nonce is invalid");
        }
        this.nonce = nonce;
        this.ciphertext = requireNonNull(ciphertext, "ciphertext");
    }

    /**
     * Constructs a CryptoBox object from the given nonce and combined ciphertext with authentication tag.
     *
     * @param nonce the nonce.
     * @param ciphertextWithTag the combined ciphertext and authentication tag.
     * @return the reconstructed crypto box.
     */
    public static CryptoBox fromCombined(byte[] nonce, byte[] ciphertextWithTag) {
        byte[] ciphertext = new byte[ciphertextWithTag.length + XSalsa20Poly1305.TAG_OFFSET];
        System.arraycopy(ciphertextWithTag, 0, ciphertext, XSalsa20Poly1305.TAG_OFFSET, ciphertextWithTag.length);
        return new CryptoBox(nonce, ciphertext);
    }

    /**
     * Constructs a CryptoBox object from the given nonce, ciphertext, and authentication tag components.
     *
     * @param nonce the nonce.
     * @param ciphertext the ciphertext.
     * @param tag the tag.
     * @return the reconstructed crypto box.
     */
    public static CryptoBox fromDetached(byte[] nonce, byte[] ciphertext, byte[] tag) {
        byte[] combined = new byte[ciphertext.length + tag.length + XSalsa20Poly1305.TAG_OFFSET];
        System.arraycopy(tag, 0, combined, XSalsa20Poly1305.TAG_OFFSET, tag.length);
        System.arraycopy(ciphertext, 0, combined, XSalsa20Poly1305.TAG_OFFSET + tag.length, ciphertext.length);
        return new CryptoBox(nonce, combined);
    }

    /**
     * Verifies and decrypts the box to reveal the plaintext message.
     *
     * @param ourPrivateKey the private key of the recipient.
     * @param sender the sender's public key.
     * @return the decrypted message.
     * @throws IllegalArgumentException if a key is invalid or if the message cannot be authenticated.
     */
    public byte[] decrypt(PrivateKey ourPrivateKey, PublicKey sender) {
        byte[] key = agreeKey(ourPrivateKey, sender);
        byte[] temp = ciphertext.clone();
        try {
            return XSalsa20Poly1305.decrypt(key, nonce, temp);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(temp, (byte) 0);
        }
    }

    /**
     * Verifies and decrypts the box to reveal the plaintext message as a UTF-8 string.
     *
     * @param ourPrivateKey the private key of the recipient.
     * @param sender the sender's public key.
     * @return the decrypted message.
     * @throws IllegalArgumentException if a key is invalid or if the message cannot be authenticated.
     */
    public String decryptToString(PrivateKey ourPrivateKey, PublicKey sender) {
        return new String(decrypt(ourPrivateKey, sender), StandardCharsets.UTF_8);
    }

    /**
     * Returns the authentication tag associated with this crypto box. The returned value is a copy.
     *
     * @return the authentication tag.
     */
    public byte[] getTag() {
        return Arrays.copyOfRange(ciphertext, XSalsa20Poly1305.TAG_OFFSET,
                XSalsa20Poly1305.TAG_OFFSET + XSalsa20Poly1305.TAG_SIZE);
    }

    /**
     * Returns the nonce that was used to encrypt this crypto box. The returned value is a copy.
     *
     * @return the nonce.
     */
    public byte[] getNonce() {
        return nonce.clone();
    }

    /**
     * Returns the ciphertext with the prepended authentication tag. The returned value is a copy.
     *
     * @return the ciphertext with the authentication tag.
     */
    public byte[] getCiphertextWithTag() {
        return Arrays.copyOfRange(ciphertext, XSalsa20Poly1305.TAG_OFFSET, ciphertext.length);
    }

    /**
     * Returns the ciphertext without the authentication tag. The returned value is a copy.
     *
     * @return the ciphertext.
     */
    public byte[] getCiphertextWithoutTag() {
        return Arrays.copyOfRange(ciphertext, XSalsa20Poly1305.TAG_OFFSET + XSalsa20Poly1305.TAG_SIZE,
                ciphertext.length);
    }

    /**
     * Writes the nonce, authentication tag, and ciphertext to the given output stream. This method writes the
     * 24-byte nonce, followed by a 4-byte little-endian length field, followed by the authentication tag and
     * ciphertext. The length field is the length of the combined authentication tag and ciphertext, in bytes.
     *
     * @param out the output stream.
     * @return the total number of bytes that were written to the output stream.
     * @throws IOException if an error occurs.
     */
    public int writeTo(OutputStream out) throws IOException {
        out.write(nonce);
        byte[] len = new byte[4];
        ByteBuffer.wrap(len).order(ByteOrder.LITTLE_ENDIAN).putInt(ciphertext.length - 16);
        out.write(len);
        out.write(ciphertext, 16, ciphertext.length - 16);

        return nonce.length + ciphertext.length + 4;
    }

    /**
     * Reads a cryptobox from the input stream using the same format as {@link #writeTo(OutputStream)}.
     *
     * @param in the input stream.
     * @return the read crypto box.
     * @throws IOException if an error occurs or the input is malformed.
     */
    public static CryptoBox readFrom(InputStream in) throws IOException {
        byte[] nonce = in.readNBytes(XSalsa20Poly1305.NONCE_LEN);
        byte[] lenBytes = in.readNBytes(4);
        int len = ByteBuffer.wrap(lenBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (len < 0) throw new IOException("invalid ciphertext length");
        byte[] ciphertext = new byte[len + XSalsa20Poly1305.TAG_OFFSET];
        int read = in.readNBytes(ciphertext, XSalsa20Poly1305.TAG_OFFSET, len);
        if (read != len) {
            throw new IOException("short read");
        }
        return new CryptoBox(nonce, ciphertext);
    }

    @Override
    public String toString() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce) + '.' +
                Base64.getUrlEncoder().withoutPadding().encodeToString(getCiphertextWithTag());
    }

    /**
     * Wipes the ciphertext and nonce from memory.
     */
    @Override
    public void close() {
        Arrays.fill(ciphertext, (byte) 0);
        Arrays.fill(nonce, (byte) 0);
    }

    private static class SeedSecureRandom extends SecureRandomSpi {

        private byte[] seed;

        SeedSecureRandom(byte[] seed) {
            this.seed = seed;
        }

        @Override
        protected void engineSetSeed(byte[] seed) {
            // Ignore
        }

        @Override
        protected synchronized void engineNextBytes(byte[] bytes) {
            if (seed == null) {
                throw new IllegalStateException("seed data exhausted");
            }
            byte[] data = SHA512.hash(seed, bytes.length);
            System.arraycopy(data, 0, bytes, 0, bytes.length);
            Arrays.fill(data, (byte) 0);
            Arrays.fill(seed, (byte) 0);
            seed = null;
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            throw new UnsupportedOperationException();
        }
    }
}
