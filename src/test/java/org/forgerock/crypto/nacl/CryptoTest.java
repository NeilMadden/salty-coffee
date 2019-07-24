/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CryptoTest {

    private static KeyPair signingKeys;

    @BeforeClass
    public void generateKeys() {
        signingKeys = Crypto.signingKeyPair();
    }

    @Test
    public void shouldProduceAValidCryptoBox() {
        KeyPair aliceKeys = CryptoBox.keyPair();
        KeyPair bobKeys = CryptoBox.keyPair();
        String message = "Hello, World!";

        CryptoBox box = Crypto.box(aliceKeys.getPrivate(), bobKeys.getPublic(), message.getBytes(UTF_8));
        String decrypted = box.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic());

        assertThat(decrypted).isEqualTo(message);
    }

    @Test
    public void shouldProduceAValidSecretBox() {
        SecretKey key = SecretBox.key();
        String message = "Hello, World!";

        SecretBox box = Crypto.box(key, message.getBytes(UTF_8));
        String decrypted = box.decryptToString(key);

        assertThat(decrypted).isEqualTo(message);
    }

    @Test
    public void shouldProduceValidSHA512Hashes() {
        String message = "A test message of SHA-512 hashing";
        String expected = "5d296d873e0ec13ee5471da483216fd0d0668209eae2251eba4f85c57ad2f59" +
                "aee860a36c4ef12fa9c4bf0f7ce39f6d640bae930deabc637691bba9b7f51fe15";

        byte[] hash = Crypto.hash(message.getBytes(UTF_8));

        assertThat(hash).isEqualTo(fromHex(expected));
    }

    @Test
    public void shouldProduceValidHMACTags() {
        SecretKey key = Crypto.authKey(fromHex("c3b065133c901043411036e9f0b69287c85ca37ce4289236469180f5ef7b9c64"));
        String message = "This is a test of the emergency broadcast system";
        String expected = "324008a433d64824f8791a5dadfe13d808a246ae6ceee5472621ff3ec2567ee8";

        byte[] tag = Crypto.auth(key, message.getBytes(UTF_8));

        assertThat(tag).isEqualTo(fromHex(expected));
    }

    @Test
    public void shouldValidateCorrectAuthTags() {
        SecretKey key = Crypto.authKey(fromHex("c3b065133c901043411036e9f0b69287c85ca37ce4289236469180f5ef7b9c64"));
        String message = "This is a test of the emergency broadcast system";
        String expected = "324008a433d64824f8791a5dadfe13d808a246ae6ceee5472621ff3ec2567ee8";

        assertThat(Crypto.authVerify(key, message.getBytes(UTF_8), fromHex(expected))).isTrue();
    }

    @DataProvider
    public Object[][] validAuthTags() {
        SecretKey key = Crypto.authKeyGen();
        Object[][] cases = new Object[100][];

        for (int i = 0; i < 100; ++i) {
            byte[] msg = Bytes.secureRandom(100);
            cases[i] = new Object[]{ key, msg, Crypto.auth(key, msg) };
        }

        return cases;
    }

    @Test(dataProvider = "validAuthTags")
    public void shouldRejectInvalidAuthTags(SecretKey key, byte[] msg, byte[] validTag) {
        assertThat(Crypto.authVerify(key, msg, validTag)).isTrue();
        assertThat(Crypto.authVerify(key, msg, Arrays.copyOf(validTag, 31))).isFalse();
        assertThat(Crypto.authVerify(key, msg, Arrays.copyOfRange(validTag, 1, 32))).isFalse();
        assertThat(Crypto.authVerify(key, Arrays.copyOf(msg, msg.length - 1), validTag)).isFalse();
        assertThat(Crypto.authVerify(key, Arrays.copyOfRange(msg, 1, msg.length), validTag)).isFalse();
        assertThat(Crypto.authVerify(key, mutate(msg), validTag)).isFalse();
        assertThat(Crypto.authVerify(key, msg, mutate(validTag))).isFalse();
    }

    @Test
    public void shouldVerifyValidSignatures() {
        for (int i = 0; i < 100; ++i) {
            byte[] msg = Bytes.secureRandom(1000);
            byte[] sig = Crypto.sign(signingKeys.getPrivate(), msg);
            assertThat(Crypto.signVerify(signingKeys.getPublic(), msg, sig)).isTrue();
        }
    }

    private static byte[] mutate(byte[] input) {
        // Flip a single bit in the input
        int index = ThreadLocalRandom.current().nextInt(input.length);
        byte[] output = input.clone();
        output[index] ^= 0x01;
        return output;
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new BigInteger(hex, 16).toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}