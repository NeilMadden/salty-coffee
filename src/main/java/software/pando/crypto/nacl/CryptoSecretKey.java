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
import java.io.IOException;
import java.io.NotSerializableException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * An alternative to {@link javax.crypto.spec.SecretKeySpec} that actually implements the {@link Destroyable#destroy()}
 * method by wiping data from memory. This is a best-effort attempt to wipe data, because the JVM may have copied the
 * key material during garbage collection, or it may have been swapped to disk, etc. In future this class may include
 * other measures, such as using off-heap memory (direct byte buffer) or obfuscation to protect key material.
 * <p>
 * Because Java APIs use mutable byte arrays (and not say, immutable byte slices), this class performs defensive copying
 * of the key material during construction and for {@link #getEncoded()} calls. The caller should take care to wipe
 * those byte arrays after use. The APIs within Salty Coffee take care to always wipe these temporary arrays, but the
 * Java Cryptography API typically doesn't.
 * <p>
 * This class maintains some limited compatibility with {@link javax.crypto.spec.SecretKeySpec}. In particular, the
 * {@link #equals(Object)} method is compatible: equivalent keys will be seen as equal. However, {@link #hashCode()} is
 * not equivalent because the SecretKeySpec implementation leaks information about the key material.
 */
final class CryptoSecretKey implements SecretKey, AutoCloseable {
    private static final long serialVersionUID = 1L;

    private final byte[] keyMaterial;
    private final String algorithm;
    private final int hashCode;

    private volatile boolean destroyed = false;

    CryptoSecretKey(byte[] keyMaterial, int offset, int length, String algorithm) {
        this.keyMaterial = Arrays.copyOfRange(keyMaterial, offset, offset + length);
        this.algorithm = algorithm;
        this.hashCode = Arrays.hashCode(Crypto.hash(this.keyMaterial)) ^ algorithm.toLowerCase(Locale.ROOT).hashCode();
    }

    CryptoSecretKey(byte[] keyMaterial, String algorithm) {
        this(keyMaterial, 0, keyMaterial.length, algorithm);
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return algorithm;
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return keyMaterial.clone();
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(keyMaterial, (byte) 0);
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public boolean equals(Object other) {
        checkDestroyed();
        if (this == other) {
            return true;
        }
        if (!(other instanceof SecretKey)) {
            return false;
        }
        var that = (SecretKey) other;

        if (!"RAW".equalsIgnoreCase(that.getFormat())) {
            return false;
        }

        var encoded = that instanceof CryptoSecretKey ? ((CryptoSecretKey) that).keyMaterial : that.getEncoded();
        try {
            return algorithm.equalsIgnoreCase(that.getAlgorithm()) && MessageDigest.isEqual(keyMaterial, encoded);
        } finally {
            if (!(that instanceof CryptoSecretKey)) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    @Override
    public int hashCode() {
        checkDestroyed();
        return hashCode;
    }

    @Override
    public String toString() {
        return "CryptoSecretKey{" +
                "algorithm='" + algorithm + "', " +
                "destroyed=" + isDestroyed() + ", " +
                "keySize=" + keyMaterial.length * 8 + " bits" +
                '}';
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Key has been destroyed");
        }
    }

    // The SecretKey interface extends Serializable. Java serialization is inherently insecure, so we override these
    // methods to prevent it.
    private void readObject(java.io.ObjectInputStream stream) throws IOException, ClassNotFoundException {
        throw new NotSerializableException(getClass().getName());
    }
    private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
        throw new NotSerializableException(getClass().getName());
    }
}
