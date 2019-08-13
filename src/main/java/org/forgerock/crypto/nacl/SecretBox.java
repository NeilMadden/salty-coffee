/*
 * Copyright 2019 Neil Madden.
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

package org.forgerock.crypto.nacl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;

/**
 * A secret box encrypts and authenticates a message using symmetric cryptography. The same key is used for both
 * encryption and decryption. See {@link CryptoBox} for public key encryption.
 * <h2>Key Generation</h2>
 * <pre>{@code
 * Key key = SecretBox.key();
 * }</pre>
 * This generates a unique 32-byte secret key.
 *
 * <h2>Encrypting a message</h2>
 * <pre>{@code
 * byte[] message = ...; // Or String message
 * SecretBox box = SecretBox.encrypt(key, message);
 * }</pre>
 *
 * A unique random nonce will be generated on each call, or you can use
 * {@link #encrypt(Key, byte[], byte[])} to specify the 24-byte nonce manually but <strong>it must
 * be unique for every call with the same key</strong>. Reusing a nonce undermines the security
 * guarantees. It is recommended to let the library generate random nonces for you.
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
 * SecretBox box = SecretBox.readFrom(in);
 * byte[] msg = box.decrypt(key);
 * // Or:
 * String msg = box.decryptToString(key);
 * }</pre>
 * You can use either {@link #decrypt(Key)} or {@link #decryptToString(Key)} to decrypt the message. The latter
 * assumes the string is UTF-8 encoded.
 *
 * <h2>Algorithms</h2>
 * Secret boxes use the XSalsa20 stream cipher for encryption along with the Poly1305 message authentication code for
 * authentication.
 */
public final class SecretBox implements AutoCloseable {

    /**
     * Generates a fresh random key. Use {@link SecretKey#destroy()} to wipe the key from memory when no longer
     * required.
     *
     * @return the random key.
     */
    public static SecretKey key() {
        return key(Bytes.secureRandom(XSalsa20Poly1305.KEY_SIZE));
    }

    /**
     * Converts a 32-byte key into a key object. The key bytes will be copied and the input array will be filled with
     * zero bytes. Use {@code key(bytes.clone())} if you wish to preserve the original key data array. Use
     * {@link SecretKey#destroy()} to wipe the key from memory when no longer required.
     *
     * @param key the key data.
     * @return the key object.
     */
    public static SecretKey key(byte[] key) {
        if (key == null || key.length != XSalsa20Poly1305.KEY_SIZE) {
            throw new IllegalArgumentException("invalid key");
        }
        try {
            return new CryptoSecretKey(key, XSalsa20Poly1305.ALGORITHM);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Encrypts the given message with the given key and nonce. The nonce <strong>must be unique</strong> for every
     * call to this method with the same key. It is recommended to use {@link #encrypt(Key, byte[])} and let the
     * library generate a nonce for you.
     *
     * @param key the key.
     * @param nonce the 24-byte nonce.
     * @param message the message to encrypt.
     * @return the encrypted box.
     */
    public static SecretBox encrypt(Key key, byte[] nonce, byte[] message) {
        if (key == null || !XSalsa20Poly1305.ALGORITHM.equals(key.getAlgorithm()) || key.getEncoded() == null ||
                key.getEncoded().length != XSalsa20Poly1305.KEY_SIZE) {
            throw new IllegalArgumentException("invalid key");
        }
        if (nonce == null || nonce.length != XSalsa20Poly1305.NONCE_LEN) {
            throw new IllegalArgumentException("invalid nonce");
        }
        if (message == null) {
            throw new NullPointerException("invalid message");
        }

        return new SecretBox(nonce, XSalsa20Poly1305.encrypt(key.getEncoded(), nonce, message));
    }

    /**
     * Encrypts the given message with the given key. A fresh 24-byte random nonce will be generated for each message,
     * which you can retrieve via {@link #getNonce()}.
     *
     * @param key the key.
     * @param message the message to encrypt.
     * @return the encrypted box.
     */
    public static SecretBox encrypt(Key key, byte[] message) {
        return encrypt(key, Bytes.secureRandom(XSalsa20Poly1305.NONCE_LEN), message);
    }

    /**
     * Encrypts the UTF-8 bytes of the given message with the given key. A fresh 24-byte random nonce will be generated
     * for each message, which you can retrieve via {@link #getNonce()}.
     *
     * @param key the key.
     * @param message the message to encrypt.
     * @return the encrypted box.
     */
    public static SecretBox encrypt(Key key, String message) {
        return encrypt(key, message.getBytes(StandardCharsets.UTF_8));
    }

    private final byte[] nonce;
    private final byte[] ciphertext;

    private SecretBox(byte[] nonce, byte[] ciphertext) {
        if (nonce == null || nonce.length != XSalsa20Poly1305.NONCE_LEN) {
            throw new IllegalArgumentException("invalid nonce");
        }
        if (ciphertext == null) {
            throw new NullPointerException("invalid ciphertext");
        }
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    /**
     * Constructs a SecretBox object from the given nonce and combined ciphertext with authentication tag.
     *
     * @param nonce the nonce.
     * @param ciphertextWithTag the combined ciphertext and authentication tag.
     * @return the reconstructed crypto box.
     */
    public static SecretBox fromCombined(byte[] nonce, byte[] ciphertextWithTag) {
        byte[] ciphertext = new byte[ciphertextWithTag.length + XSalsa20Poly1305.TAG_OFFSET];
        System.arraycopy(ciphertextWithTag, 0, ciphertext, XSalsa20Poly1305.TAG_OFFSET, ciphertextWithTag.length);
        return new SecretBox(nonce, ciphertext);
    }

    /**
     * Constructs a SecretBox object from the given nonce, ciphertext, and authentication tag components.
     *
     * @param nonce the nonce.
     * @param ciphertext the ciphertext.
     * @param tag the tag.
     * @return the reconstructed crypto box.
     */
    public static SecretBox fromDetached(byte[] nonce, byte[] ciphertext, byte[] tag) {
        byte[] combined = new byte[ciphertext.length + tag.length + XSalsa20Poly1305.TAG_OFFSET];
        System.arraycopy(tag, 0, combined, XSalsa20Poly1305.TAG_OFFSET, tag.length);
        System.arraycopy(ciphertext, 0, combined, XSalsa20Poly1305.TAG_OFFSET + tag.length, ciphertext.length);
        return new SecretBox(nonce, combined);
    }

    /**
     * Verifies and decrypts the box to reveal the plaintext message.
     *
     * @param key the decryption key.
     * @return the decrypted message.
     * @throws IllegalArgumentException if the key is invalid or the message is not authentic.
     */
    public byte[] decrypt(Key key) {
        if (key == null || !XSalsa20Poly1305.ALGORITHM.equals(key.getAlgorithm()) || key.getEncoded() == null ||
                key.getEncoded().length != XSalsa20Poly1305.KEY_SIZE) {
            throw new IllegalArgumentException("invalid key");
        }
        byte[] temp = ciphertext.clone();
        try {
            return XSalsa20Poly1305.decrypt(key.getEncoded(), nonce, temp);
        } finally {
            Arrays.fill(temp, (byte) 0);
        }
    }

    /**
     * Verifies and decrypts the box to reveal the plaintext message as a UTF-8 string.
     *
     * @param key the decryption key.
     * @return the decrypted message as a UTF-8 string.
     * @throws IllegalArgumentException if the key is invalid or the message is not authentic.
     */
    public String decryptToString(Key key) {
        return new String(decrypt(key), StandardCharsets.UTF_8);
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
    public static SecretBox readFrom(InputStream in) throws IOException {
        byte[] nonce = in.readNBytes(XSalsa20Poly1305.NONCE_LEN);
        byte[] lenBytes = in.readNBytes(4);
        int len = ByteBuffer.wrap(lenBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (len < 0) throw new IOException("invalid ciphertext length");
        byte[] ciphertext = new byte[len + XSalsa20Poly1305.TAG_OFFSET];
        int read = in.readNBytes(ciphertext, XSalsa20Poly1305.TAG_OFFSET, len);
        if (read != len) {
            throw new IOException("short read");
        }
        return new SecretBox(nonce, ciphertext);
    }

    /**
     * Reconstructs a SecretBox from the {@link #toString()} form.
     *
     * @param encoded the encoded string.
     * @return the decoded SecretBox.
     * @throws IllegalArgumentException if the string is invalid.
     */
    public static SecretBox fromString(String encoded) {
        int index = encoded.indexOf('.');
        if (index == -1) {
            throw new IllegalArgumentException("invalid encoded secretbox");
        }
        return SecretBox.fromCombined(Base64.getUrlDecoder().decode(encoded.substring(0, index)),
                Base64.getUrlDecoder().decode(encoded.substring(index + 1)));
    }

    /**
     * Writes the SecretBox as a URL-safe Base64-encoded string.
     *
     * @return the encoded string form.
     */
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

}
