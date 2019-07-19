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
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Generic utilities for operating on byte arrays that may contain secret data.
 */
public final class Bytes {
    private static final SecureRandom SECURE_RANDOM_SOURCE = getSecureRandomInstance();

    /**
     * Compares two byte arrays for equality without leaking secrets through timing variations. In particular, if
     * one of the inputs is secret then the time taken is constant regardless of the value or length other argument.
     *
     * @param a the first byte array.
     * @param b the second byte array.
     * @return whether the two arrays are equal.
     */
    public static boolean equal(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Generates the given number of cryptographically secure random bytes.
     *
     * @param numBytes the number of bytes to generate.
     * @return the generated secure random bytes.
     */
    public static byte[] secureRandom(int numBytes) {
        // NB: Java's SecureRandom framework goes out of its way to mix random data into its crazy old SHA1PRNG
        // algorithm, even when you request the NativePRNG. We therefore use generateSeed, which bypasses this and
        // returns the entropy directly from the underlying entropy source.
        return SECURE_RANDOM_SOURCE.generateSeed(numBytes);
    }

    /**
     * Reverses the given byte array in-place. As a convenience it also returns the same array.
     *
     * @param bytes the bytes to reverse.
     * @return the reversed array.
     */
    static byte[] reverse(byte[] bytes) {
        for (int i = 0; i < bytes.length >> 1; ++i) {
            swap(bytes, i, bytes.length - i - 1);
        }
        return bytes;
    }

    /**
     * Concatenates two byte arrays. A new array is always created even if one of the arguments is zero-length.
     *
     * @param a the first byte array.
     * @param b the second byte array.
     * @return the concatenation of the two byte arrays.
     */
    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Swaps two elements of a byte array.
     */
    private static void swap(byte[] bytes, int x, int y) {
        bytes[x] ^= bytes[y];
        bytes[y] ^= bytes[x];
        bytes[x] ^= bytes[y];
    }

    private static SecureRandom getSecureRandomInstance() {
        final String[] PREFERRED_PRNGS = {
                "NativePRNGNonBlocking", "NativePRNG", "DRBG"
        };
        for (String alg : PREFERRED_PRNGS) {
            try {
                return SecureRandom.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                // Skip this one
            }
        }

        if (System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows")) {
            // On Windows use the SHA1PRNG. While this is a weak algorithm, the default seed source on Windows is
            // native code that calls CryptGenRandom(). By using SecureRandom.generateSeed() we will bypass the
            // weak SHA1PRNG and go straight to this high-quality seed generator.
            try {
                return SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException e) {
                // Skip this one
            }
        }

        throw new IllegalStateException("Unable to find a high-quality SecureRandom source");
    }

}
