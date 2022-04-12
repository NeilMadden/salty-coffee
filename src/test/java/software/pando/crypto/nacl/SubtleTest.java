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

import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.SoftAssertions.assertSoftly;
import static org.assertj.core.internal.Digests.fromHex;
import static software.pando.crypto.nacl.Salsa20Test.bytes;

public class SubtleTest {

    @Test
    public void testConstants() {
        assertSoftly(softly -> {
            softly.assertThat(Subtle.XSALSA20_KEY_SIZE).isEqualTo(32);
            softly.assertThat(Subtle.XSALSA20_NONCE_SIZE).isEqualTo(24);
        });
    }

    @Test
    public void scalarMultiplicationShouldMatchRfc7748TestVector1() {
        byte[] scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] point = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] result = Subtle.scalarMultiplication(scalar, point);
        assertThat(result).asHexString()
                .isEqualToIgnoringCase("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    @Test
    public void scalarMultiplicationShouldMatchRfc7748TestVector2() {
        byte[] scalar = fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        byte[] point = fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        byte[] result = Subtle.scalarMultiplication(scalar, point);
        assertThat(result).asHexString()
                .isEqualToIgnoringCase("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }

    @Test
    public void scalarMultiplicationShouldMatchRfc7748IteratedTestVectorAfter1Round() {
        byte[] scalar = fromHex("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] point = fromHex("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] result = Subtle.scalarMultiplication(scalar, point);
        assertThat(result).asHexString()
                .isEqualToIgnoringCase("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    }

    @Test
    public void scalarMultiplicationShouldMatchRfc7748IteratedTestVectorAfter1000Rounds() {
        byte[] scalar = fromHex("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] point = fromHex("0900000000000000000000000000000000000000000000000000000000000000");

        for (int i = 0; i < 1000; ++i) {
            byte[] tmp = Subtle.scalarMultiplication(scalar, point);
            point = scalar;
            scalar = tmp;
        }
        assertThat(scalar).asHexString()
                .isEqualToIgnoringCase("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }

    @Test(enabled = false) // This test is extremely slow and CPU-intensive so disabled by default
    public void scalarMultiplicationShouldMatchRfc7748IteratedTestVectorAfter1000000Rounds() {
        byte[] scalar = fromHex("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] point = fromHex("0900000000000000000000000000000000000000000000000000000000000000");

        for (int i = 0; i < 1_000_000; ++i) {
            byte[] tmp = Subtle.scalarMultiplication(scalar, point);
            point = scalar;
            scalar = tmp;
        }
        assertThat(scalar).asHexString()
                .isEqualToIgnoringCase("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
    }

    @Test
    public void streamShouldMatchLibsodiumTestVector1() {
        // Given
        byte[] firstkey = bytes(
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
                0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89);
        byte[] nonce = bytes(
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
                0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37);
        ByteSlice output = ByteSlice.of(new byte[4194304]);

        // When
        Subtle.streamXSalsa20(Subtle.streamXSalsa20Key(firstkey), nonce).process(output);

        // Then
        assertThat(sha256(output.array)).asHexString()
                .isEqualToIgnoringCase("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");
    }

    private static byte[] sha256(byte[] data) {
        try {
            var hash = MessageDigest.getInstance("SHA-256");
            return hash.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}