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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptoSecretKeyTest {
    private static final byte[] KEY_DATA = new byte[32];
    static {
        for (int i = 0; i < KEY_DATA.length; ++i) {
            KEY_DATA[i] = (byte) i;
        }
    }

    @Test
    public void shouldUseEntireByteArrayIfRangeNotSpecified() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        // When
        var keyData = key.getEncoded();

        // Then
        assertThat(keyData).isEqualTo(KEY_DATA);
    }

    @Test
    public void shouldUseSpecifiedRangeOfKeyMaterial() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), 5, 10, "AES");

        // When
        var keyData = key.getEncoded();

        // Then
        assertThat(keyData).isEqualTo(Arrays.copyOfRange(KEY_DATA, 5, 15));
    }

    @Test
    public void shouldTakeDefensiveCopyOfInputKeyMaterial() {
        // Given
        var originalKeyData = KEY_DATA.clone();
        var key = new CryptoSecretKey(originalKeyData, "AES");

        // When
        Arrays.fill(originalKeyData, (byte) 42);
        var result = key.getEncoded();

        // Then
        assertThat(result).isNotEqualTo(originalKeyData).isEqualTo(KEY_DATA);
    }

    @Test
    public void shouldTakeDefensiveCopyOfOutputKeyMaterial() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var encoded = key.getEncoded();

        // When
        Arrays.fill(encoded, (byte) 42);
        var result = key.getEncoded();

        // Then
        assertThat(result).isNotEqualTo(encoded).isEqualTo(KEY_DATA);
    }

    @Test
    public void shouldSupportDestroyingKeyMaterial() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        // When
        key.destroy();

        // Then
        assertThat(key.isDestroyed()).isTrue();
        assertThat(key).extracting("keyMaterial").isEqualTo(new byte[32]);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void shouldThrowExceptionIfKeyHasBeenDestroyed() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        key.destroy();

        // When
        key.getEncoded();
    }

    @Test
    public void shouldUseConsistentHashCode() {
        // Given
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key2 = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        // When
        int hashCode1 = key1.hashCode();
        int hashCode2 = key2.hashCode();

        // Then
        assertThat(hashCode1).isEqualTo(hashCode2).isEqualTo(1580929082);
    }

    @Test
    public void shouldVaryHashCodeBasedOnKeyMaterial() {
        // Given
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var alteredKeyData = KEY_DATA.clone();
        alteredKeyData[0] = 42;
        var key2 = new CryptoSecretKey(alteredKeyData, "AES");

        // When
        int hashCode1 = key1.hashCode();
        int hashCode2 = key2.hashCode();

        // Then
        assertThat(hashCode1).isNotEqualTo(hashCode2);
    }

    @Test
    public void shouldVaryHashCodeBasedOnKeyAlgorithm() {
        // Given
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key2 = new CryptoSecretKey(KEY_DATA.clone(), "HmacSHA256");

        // When
        int hashCode1 = key1.hashCode();
        int hashCode2 = key2.hashCode();

        // Then
        assertThat(hashCode1).isNotEqualTo(hashCode2);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void shouldThrowExceptionFromHashCodeIfDestroyed() {
        // Given
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        // When
        key.destroy();
        ignore(key.hashCode());

        // Then - exception
    }

    @Test
    public void equalsShouldBeReflexive() {
        var key = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        assertThat(key).isEqualTo(key);
    }

    @Test
    public void equalsShouldBeSymmetric() {
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key2 = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        assertThat(key1).isEqualTo(key2);
        assertThat(key2).isEqualTo(key1);
    }

    @Test
    public void equalsShouldBeTransitive() {
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key2 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key3 = new CryptoSecretKey(KEY_DATA.clone(), "AES");

        assertThat(key1).isEqualTo(key2);
        assertThat(key2).isEqualTo(key3);
        assertThat(key1).isEqualTo(key3);
    }

    @Test
    public void shouldNotBeEqualToNull() {
        assertThat(new CryptoSecretKey(KEY_DATA.clone(), "AES")).isNotEqualTo(null);
    }

    @Test
    public void shouldNotBeEqualIfAlgorithmIsDifferent() {
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var key2 = new CryptoSecretKey(KEY_DATA.clone(), "HmacSHA256");
        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    public void shouldNotBeEqualIfKeyDataIsDifferent() {
        var key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        var alteredKeyData = KEY_DATA.clone();
        alteredKeyData[0] = 42;
        var key2 = new CryptoSecretKey(alteredKeyData, "AES");
        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    public void shouldNotBeEqualIfFormatIsDifferent() {
        SecretKey key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        SecretKey key2 = new SecretKeySpec(KEY_DATA.clone(), "AES") {
            @Override
            public String getFormat() {
                return "special";
            }
        };
        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    public void shouldBeEqualToEquivalentSecretKeySpec() {
        SecretKey key1 = new CryptoSecretKey(KEY_DATA.clone(), "AES");
        SecretKey key2 = new SecretKeySpec(KEY_DATA.clone(), "AES");
        assertThat(key1).isEqualTo(key2);
    }

    @Test
    public void shouldReturnSpecifiedKeyAlgorithm() {
        assertThat(new CryptoSecretKey(KEY_DATA.clone(), "test").getAlgorithm()).isEqualTo("test");
    }

    @Test
    public void shouldUseRawKeyFormat() {
        assertThat(new CryptoSecretKey(KEY_DATA.clone(), "AES").getFormat()).isEqualToIgnoringCase("RAW");
    }

    private static void ignore(Object ignored) {}
}