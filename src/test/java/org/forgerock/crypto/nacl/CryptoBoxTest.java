/*
 * Copyright 2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class CryptoBoxTest {

    private KeyPair aliceKeys;
    private KeyPair bobKeys;

    @BeforeClass
    public void setupKeys() {
        // Test cases from https://cr.yp.to/highspeed/naclcrypto-20090310.pdf

        byte[] alicesk = bytes(
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a);
        byte[] bobpk = bytes(
                0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f);

        byte[] bobsk = bytes(
                0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
                0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
                0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb);
        byte[] alicepk = bytes(
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a);


        aliceKeys = new KeyPair(CryptoBox.publicKey(alicepk), CryptoBox.privateKey(alicesk));
        bobKeys = new KeyPair(CryptoBox.publicKey(bobpk), CryptoBox.privateKey(bobsk));
    }


    @Test
    public void shouldGenerateValidKeyPair() {
        KeyPair keyPair = CryptoBox.keyPair();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
    }

    @Test
    public void shouldComputeCorrectSharedSecret() {
        byte[] sharedSecret1 = CryptoBox.agreeKey(aliceKeys.getPrivate(), bobKeys.getPublic());
        byte[] sharedSecret2 = CryptoBox.agreeKey(bobKeys.getPrivate(), aliceKeys.getPublic());

        assertThat(sharedSecret1).isEqualTo(bytes(
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
                0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
                0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89));
        assertThat(sharedSecret2).isEqualTo(sharedSecret1);
    }

    @Test
    public void shouldProduceCorrectKeyStream() throws IOException {
        byte[] nonce = bytes(
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
                0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
        );

        byte[] plaintext = bytes(
                0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
                ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
                ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
                ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
                ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
                ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
                ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
                ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
                ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
                ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
                ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
                ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
                ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
                ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
                ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
                ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
                ,0x5e,0x07,0x05);

        CryptoBox encrypted = CryptoBox.encrypt(aliceKeys.getPrivate(), bobKeys.getPublic(), nonce, plaintext.clone());

        assertThat(encrypted.getCiphertextWithTag()).isEqualTo(bytes(
                0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
                ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
                ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
                ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
                ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
                ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
                ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
                ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
                ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
                ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
                ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
                ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
                ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
                ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
                ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
                ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
                ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
                ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
                ,0xe3,0x55,0xa5));

        CryptoBox received;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            encrypted.writeTo(out);
            out.flush();
            received = CryptoBox.readFrom(new ByteArrayInputStream(out.toByteArray()));
        }

        byte[] decrypted = received.decrypt(bobKeys.getPrivate(), aliceKeys.getPublic());
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    public void shouldBeIdempotentForDecryption() {
        String plaintext = "This is a test of the emergency broadcast system";

        CryptoBox box = CryptoBox.encrypt(aliceKeys.getPrivate(), bobKeys.getPublic(), plaintext);

        String decrypt1 = box.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic());
        String decrypt2 = box.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic());

        assertThat(decrypt1).isEqualTo(plaintext);
        assertThat(decrypt2).isEqualTo(plaintext);
    }

    @Test
    public void shouldBeInteroperableWithSecretBox() throws IOException {
        String plaintext = "crypto_box_afternm is the same as crypto_secretbox";

        Key secretKey = CryptoBox.agree(aliceKeys.getPrivate(), bobKeys.getPublic());
        SecretBox box1 = SecretBox.encrypt(secretKey, plaintext);

        CryptoBox box2;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            box1.writeTo(out);
            out.flush();
            box2 = CryptoBox.readFrom(new ByteArrayInputStream(out.toByteArray()));
        }

        String decrypted = box2.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic());
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    public void shouldGenerateDeterministicKeysFromASeed() {
        byte[] seed = bytes(
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a);

        KeyPair keyPair = CryptoBox.seedKeyPair(seed);

        byte[] sk = ((XECPrivateKey) keyPair.getPrivate()).getScalar().orElseThrow();
        assertThat(sk).containsExactly(
                0xac, 0xcd, 0x44, 0xeb, 0x8e, 0x93, 0x31, 0x9c,
                0x05, 0x70, 0xbc, 0x11, 0x00, 0x5c, 0x0e, 0x01,
                0x89, 0xd3, 0x4f, 0xf0, 0x2f, 0x6c, 0x17, 0x77,
                0x34, 0x11, 0xad, 0x19, 0x12, 0x93, 0xc9, 0x8f);

        byte[] pk = Bytes.reverse(((XECPublicKey) keyPair.getPublic()).getU().toByteArray());
        assertThat(pk).containsExactly(
                0xed, 0x77, 0x49, 0xb4, 0xd9, 0x89, 0xf6, 0x95,
                0x7f, 0x3b, 0xfd, 0xe6, 0xc5, 0x67, 0x67, 0xe9,
                0x88, 0xe2, 0x1c, 0x9f, 0x87, 0x84, 0xd9, 0x1d,
                0x61, 0x00, 0x11, 0xcd, 0x55, 0x3f, 0x9b, 0x06);
    }


    @Test
    public void shouldEncodeAndDecodeAsString() {
        String plaintext = "This is a test of the emergency broadcast system";

        CryptoBox box1 = CryptoBox.encrypt(aliceKeys.getPrivate(), bobKeys.getPublic(), plaintext);
        CryptoBox box2 = CryptoBox.fromString(box1.toString());

        assertThat(box2.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic())).isEqualTo(plaintext);
    }

    static byte[] bytes(int...bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; ++i) {
            result[i] = (byte) bytes[i];
        }
        return result;
    }
}