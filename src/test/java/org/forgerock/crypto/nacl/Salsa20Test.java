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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

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

    private static byte[] bytes(int...ints) {
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