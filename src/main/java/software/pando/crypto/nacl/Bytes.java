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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Generic utilities for operating on byte arrays that may contain secret data.
 */
public final class Bytes {
    private static final Collection<String> PREFERRED_PRNGS = List.of(
            "NativePRNGNonBlocking", "NativePRNG", "DRBG");
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
     * Concatenates three byte arrays. A new array is always created even if one of the arguments is zero-length.
     *
     * @param a the first byte array.
     * @param b the second byte array.
     * @param c the third byte array.
     * @return the concatenation of the two byte arrays.
     */
    static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] d = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, d, 0, a.length);
        System.arraycopy(b, 0, d, a.length, b.length);
        System.arraycopy(c, 0, d, a.length + b.length, c.length);
        return d;
    }

    /**
     * Swaps two elements of a byte array.
     */
    private static void swap(byte[] bytes, int x, int y) {
        byte tmp = bytes[x];
        bytes[x] = bytes[y];
        bytes[y] = tmp;
    }

    private static SecureRandom getSecureRandomInstance() {
        for (String alg : PREFERRED_PRNGS) {
            try {
                return SecureRandom.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                // Skip this one
            }
        }

        if (System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows")
        || (System.getProperty("os.name").equals("Linux") && System.getProperty("java.vm.vendor").equals("The Android Project"))) {
            // On Windows or Android use the SHA1PRNG. While this is a weak algorithm, the default seed source on Windows is
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
