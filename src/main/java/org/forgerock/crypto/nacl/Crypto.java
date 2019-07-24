/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

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
     * @return the secret key.
     */
    public static SecretKey authKey(byte[] keyBytes) {
        if (keyBytes.length != SHA512.HMAC_KEY_LEN) {
            throw new IllegalArgumentException("invalid key");
        }
        return new CryptoSecretKey(keyBytes, SHA512.MAC_ALGORITHM);
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
}
