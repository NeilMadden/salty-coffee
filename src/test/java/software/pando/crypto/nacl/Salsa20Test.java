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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.assertj.core.api.Assertions.assertThat;

public class Salsa20Test {

    @DataProvider
    public Object[][] quarterRoundTestVectors() {
        // See http://cr.yp.to/snuffle/spec.pdf
        return new Object[][] {
                { new int[]{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
                  new int[]{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 }},
                { new int[]{ 0x00000001, 0x00000000, 0x00000000, 0x00000000 },
                  new int[]{ 0x08008145, 0x00000080, 0x00010200, 0x20500000 }},
                { new int[]{ 0x00000000, 0x00000001, 0x00000000, 0x00000000 },
                  new int[]{ 0x88000100, 0x00000001, 0x00000200, 0x00402000 }},
                { new int[]{ 0x00000000, 0x00000000, 0x00000001, 0x00000000 },
                  new int[]{ 0x80040000, 0x00000000, 0x00000001, 0x00002000 }},
                { new int[]{ 0x00000000, 0x00000000, 0x00000000, 0x00000001 },
                  new int[]{ 0x00048044, 0x00000080, 0x00010000, 0x20100001 }},
                { new int[]{ 0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137 },
                  new int[]{ 0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3 }},
                { new int[]{ 0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b },
                  new int[]{ 0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c }}
        };
    }

    @Test(dataProvider = "quarterRoundTestVectors")
    public void shouldMatchSalsa20QuarterRoundTests(int[] initialState, int[] finalState) {
        Salsa20.quarterRound(initialState, 0, 1, 2, 3);
        assertThat(initialState).isEqualTo(finalState);
    }

    @DataProvider
    public Object[][] blockFunctionTestVectors() {
        return new Object[][]{
                { new byte[64], new byte[64] },
                { bytes(211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136, 49, 237, 179, 48, 1,
                        106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147,
                        48, 113, 238, 55, 204, 36, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104,
                        54),
                  bytes(109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154, 29, 29,150, 26,150, 30,235,
                          249,190,163,251, 48, 69,144, 51, 57, 118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,
                          111,114,114, 219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202)},
                { bytes(88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 191,187,234,136,211,159, 13,115,
                        76, 55, 82,183, 3,117,222, 37, 86, 16,179,207, 49,237,179, 48, 1,106,178,219,175,199,166, 48,
                        238, 55,204, 36, 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113),
                  bytes(179, 19, 48,202,219,236,232,135,111,155,110, 18, 24,232, 95,158, 26,110,170,154,109, 42,178,
                          168,156,240,248,238,168,196,190,203, 69,144, 51, 57, 29, 29,150, 26,150, 30,235,249,190,163,
                          251, 48,27,111,114,114,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35)}
        };
    }

    @Test(dataProvider = "blockFunctionTestVectors")
    public void shouldMatchSalsa20BlockFunctionTestVectors(byte[] input, byte[] output) {
        assert input.length == 64;
        assert output.length == 64;

        int[] state = toInts(input);

        state = Salsa20.blockFunction(state);

        assertThat(toBytes(state)).isEqualTo(output);
    }

    @Test
    public void shouldMatchIteratedBlockFunctionTestVector() {
        byte[] input = bytes(6,124, 83,146, 38,191, 9, 50, 4,161, 47,222,122,182,223,185,
                75, 27, 0,216, 16,122, 7, 89,162,104,101,147,213, 21, 54, 95, 225,253,139,176,105,132, 23,116, 76, 41
                ,176,207,221, 34,157,108, 94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186);
        byte[] output = bytes(8, 18, 38,199,119, 76,215, 67,173,127,144,162,103,212,176,217, 192, 19,233, 33,159,197,
                154,160,128,243,219, 65,171,136,135,225, 123, 11, 68, 86,237, 82, 20,155,133,189, 9, 83,167,116,194, 78,
                122,127,195,185,185,204,188, 90,245, 9,183,248,226, 85,245,104);


        int[] state = toInts(input);

        for (int i = 0; i < 1000000; ++i) {
            state = Salsa20.blockFunction(state);
        }
        assertThat(toBytes(state)).isEqualTo(output);
    }

    @Test
    public void shouldMatchInitialStateTestVector() {
        // NB we only implement 256-bit key variant
        byte[] key = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216);
        byte[] nonce = bytes(101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116);

        byte[] stateBytes = toBytes(Salsa20.initialState(key, nonce));

        assertThat(stateBytes).containsExactly(
                101,120,112, 97, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                13, 14, 15, 16,110,100, 32, 51,101,102,103,104,105,106,
                107,108, 109,110,111,112,113,114,115,116, 50, 45, 98,
                121,201,202,203,204, 205,206,207,208,209,210,211,212,
                213,214,215,216,116,101, 32,107
        );
    }

    @Test
    public void shouldHandle32BitSignedBlockCounterOverflow() {
        // Given
        byte[] key = bytes(
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85,
                0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
                0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac,
                0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
                0x44, 0xf6, 0x83, 0x89);
        byte[] nonce = bytes(
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        String expectedHex = "d9c95f12ce90f21b9e815b7cc4887a9a1ff04a7ec6365c62a8f9172b5157cd4acfb0353a7b9098dd3f47" +
                "e383bae4cfcb03b7761a282c518c0d0229402f7299a170be9276af6f231c04c62a51cc28f07c7cbc6666abf04c5758f31" +
                "51e6bf612f381b89d8b8b54869dc847ee1eaa6c1c7c9ce9c638d825c76eeabf41872f196767";

        // When
        ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
                .asLongBuffer()
                .put(1, Integer.MAX_VALUE);
        byte[] data = new byte[128];
        Salsa20.encrypt(key, nonce, data);

        // Then
        assertThat(data)
                .asHexString()
                .isEqualToIgnoringCase(expectedHex);
    }

    @Test
    public void shouldHandle32BitUnsignedBlockCounterOverflow() {
        byte[] key = bytes(
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85,
                0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
                0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac,
                0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
                0x44, 0xf6, 0x83, 0x89);
        byte[] nonce = bytes(
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        String expectedHex = "60235422f7060426a5d88fa8b10870690421b0a421b35dadf82f16949f74a53d33f7410ac10f2d787ab8" +
                "41f5c22c690c74ac9a8c519413b54419239bf0feeeab09fbecd7a61e40aa54c34f7e7346099e3b1b5f95c6195c26b268a" +
                "4532c5fce9a3d0f020d85347b816c4b0edd50c89d663bb10c4216a134309471f163758295ed";

        // When
        ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
                .asLongBuffer()
                .put(1, (1L << 32) - 1L);
        byte[] data = new byte[128];
        Salsa20.encrypt(key, nonce, data);

        // Then
        assertThat(data)
                .asHexString()
                .isEqualToIgnoringCase(expectedHex);
    }

    /**
     * Technically, XSalsa20 can support the full range of a 64-bit long as the block counter. For implementation
     * simplicity in Java, we only support up to Long.MAX_VALUE (i.e. 2^63-1). Although it is extremely unlikely that
     * this limit will ever be reached, for safety we raise an exception if it is.
     */
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shouldThrowExceptionIfBlockCounterExceedsSigned64BitLong() {
        // Given
        byte[] key = bytes(
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85,
                0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
                0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac,
                0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
                0x44, 0xf6, 0x83, 0x89);
        byte[] nonce = bytes(
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

        // When
        ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
                .asLongBuffer()
                .put(1, Long.MAX_VALUE);
        byte[] data = new byte[128];
        Salsa20.encrypt(key, nonce, data);

        // Then - exception
    }

    static byte[] bytes(int...ints) {
        byte[] bytes = new byte[ints.length];
        for (int i = 0; i < ints.length; ++i) {
            bytes[i] = (byte)(ints[i]);
        }
        return bytes;
    }

    private static int[] toInts(byte[] bytes) {
        int[] state = new int[bytes.length / 4];
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        buf.asIntBuffer().get(state);
        return state;
    }

    private static byte[] toBytes(int[] state) {
        ByteBuffer buf = ByteBuffer.allocate(state.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        buf.asIntBuffer().put(state);
        return buf.array();
    }
}