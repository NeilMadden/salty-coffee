/*
 * Copyright 2019-2023 Neil Madden.
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

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.internal.Digests.fromHex;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

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

    @Test(dataProvider = "validAuthTags")
    public void authMultiShouldNotAcceptNormalAuthTags(SecretKey key, byte[] message, byte[] normalAuthTag) {
        assertThat(Crypto.authVerifyMulti(key, List.of(message), normalAuthTag)).isFalse();
    }

    @Test
    public void authMultiShouldOnlyCallIteratorOnce() {
        // Given
        var blocks = List.of(new byte[]{1}, new byte[]{2});
        var count = new AtomicInteger();
        Iterable<byte[]> iterable = () -> {
            count.incrementAndGet();
            return blocks.iterator();
        };

        // When
        Crypto.authMulti(Crypto.authKeyGen(), iterable);

        // Then
        assertThat(count).hasValue(1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void authMultiShouldRejectNullBlocks() {
        Crypto.authMulti(Crypto.authKeyGen(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void authMultiShouldRejectNullKey() {
        Crypto.authMulti(null, List.of(new byte[0]));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void authMultiShouldRejectEmptyBlocks() {
        Crypto.authMulti(Crypto.authKeyGen(), List.of());
    }

    @Test(dataProvider = "validAuthTags")
    public void authMultiShouldProduceDifferentTagsToNormalAuth(SecretKey key, byte[] message, byte[] normalTag) {
        assertThat(Crypto.authMulti(key, List.of(message))).isNotEqualTo(normalTag);
    }

    @DataProvider
    public Object[][] validAuthMultiTags() {
        var key = Crypto.authKeyGen();
        var results = new ArrayList<Object[]>(100);
        for (int i = 0; i < 100; ++i) {
            var numBlocks = ThreadLocalRandom.current().nextInt(1, 6);
            var blocks = new ArrayList<byte[]>();
            for (int j = 0; j < numBlocks; ++j) {
                var block = Bytes.secureRandom(ThreadLocalRandom.current().nextInt(1, 100));
                blocks.add(block);
            }
            results.add(new Object[] { key, blocks, Crypto.authMulti(key, blocks)});
        }
        return results.toArray(Object[][]::new);
    }

    @Test(dataProvider = "validAuthMultiTags")
    public void authMultiShouldVerifyCorrectTags(SecretKey key, List<byte[]> blocks, byte[] validTag) {
        assertThat(Crypto.authVerifyMulti(key, blocks, validTag)).isTrue();
    }

    @Test(dataProvider = "validAuthMultiTags")
    public void authMultiShouldRejectInvalidTags(SecretKey key, List<byte[]> blocks, byte[] validTag) {
        assertThat(Crypto.authVerifyMulti(key, blocks, Arrays.copyOf(validTag, 31))).isFalse();
        assertThat(Crypto.authVerifyMulti(key, blocks, Arrays.copyOfRange(validTag, 1, 32))).isFalse();
        assertThat(Crypto.authVerifyMulti(key,
                changeRandomBlock(blocks, msg -> Arrays.copyOf(msg, msg.length - 1)), validTag)).isFalse();
        assertThat(Crypto.authVerifyMulti(key,
                changeRandomBlock(blocks, msg -> Arrays.copyOfRange(msg, 1, msg.length)), validTag)).isFalse();
        assertThat(Crypto.authVerifyMulti(key,
                changeRandomBlock(blocks, CryptoTest::mutate), validTag)).isFalse();
        assertThat(Crypto.authVerifyMulti(key, blocks, mutate(validTag))).isFalse();
        if (blocks.size() > 1) {
            assertThat(Crypto.authVerifyMulti(key, blocks.subList(1, blocks.size()), validTag)).isFalse();
            assertThat(Crypto.authVerifyMulti(key, blocks.subList(0, blocks.size() - 1), validTag)).isFalse();
        }
    }

    private static List<byte[]> changeRandomBlock(List<byte[]> blocks, Function<byte[], byte[]> mutator) {
        int blockNum = ThreadLocalRandom.current().nextInt(blocks.size());
        byte[] block = mutator.apply(blocks.get(blockNum));
        var result = new ArrayList<>(blocks);
        result.set(blockNum, block);
        return result;
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

    @Test
    public void shouldProduceValidSipHashKeys() {
        SecretKey hashKey = Crypto.shortHashKeyGen();
        assertThat(hashKey)
                .isNotNull()
                .hasFieldOrPropertyWithValue("algorithm", "SipHash")
                .hasFieldOrPropertyWithValue("format", "RAW");
        assertThat(hashKey.getEncoded())
                .isNotNull()
                .hasSize(16)
                .isNotEqualTo(new byte[16]);
    }

    @Test
    public void shouldProduceValidSipHashOutputs() {
        SecretKey key = Crypto.shortHashKey(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F });
        byte[] input = new byte[] { 0 };
        byte[] expected = new byte[] {
                (byte) 0xfd, 0x67, (byte) 0xdc, (byte) 0x93, (byte) 0xc5, 0x39, (byte) 0xf8, 0x74 };
        byte[] computed = Crypto.shortHash(key, input);
        assertThat(computed).isEqualTo(expected);
    }
}