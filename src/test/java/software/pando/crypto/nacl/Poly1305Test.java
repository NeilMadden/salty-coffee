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

package software.pando.crypto.nacl;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class Poly1305Test {

    @Test
    public void shouldMatchRfcTestVector() {
        byte[] key = fromHex(
                "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
        String msg = "Cryptographic Forum Research Group";
        byte[] tag = fromHex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");

        assertThat(Poly1305.compute(key, msg.getBytes(StandardCharsets.US_ASCII), 0, msg.length())).isEqualTo(tag);
    }

    @DataProvider
    public Object[][] validAuthTags() {
        byte[] key = Bytes.secureRandom(32);
        Object[][] cases = new Object[100][];

        for (int i = 0; i < 100; ++i) {
            byte[] msg = Bytes.secureRandom(100);
            cases[i] = new Object[]{ key, msg, Poly1305.compute(key, msg, 0, msg.length) };
        }

        return cases;
    }

    @Test(dataProvider = "validAuthTags")
    public void shouldRejectInvalidAuthTags(byte[] key, byte[] msg, byte[] validTag) {
        assertThat(Poly1305.verify(key, msg, validTag)).isTrue();
        assertThat(Poly1305.verify(key, msg, Arrays.copyOf(validTag, 31))).isFalse();
        assertThat(Poly1305.verify(key, msg, Arrays.copyOfRange(validTag, 1, 32))).isFalse();
        assertThat(Poly1305.verify(key, Arrays.copyOf(msg, msg.length - 1), validTag)).isFalse();
        assertThat(Poly1305.verify(key, Arrays.copyOfRange(msg, 1, msg.length), validTag)).isFalse();
        assertThat(Poly1305.verify(key, mutate(msg), validTag)).isFalse();
        assertThat(Poly1305.verify(key, msg, mutate(validTag))).isFalse();
    }

    private static byte[] mutate(byte[] input) {
        // Flip a single bit in the input
        int index = ThreadLocalRandom.current().nextInt(input.length);
        byte[] output = input.clone();
        output[index] ^= 0x01;
        return output;
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new BigInteger(hex.replaceAll("[^0-9a-fA-F]", ""), 16).toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

}