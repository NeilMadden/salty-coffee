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

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class BytesTest {

    @DataProvider
    public Object[][] equalsTestCases() {
        return new Object[][]{
                {null, null, true},
                {new byte[0], new byte[0], true},
                {new byte[1], new byte[1], true},
                {new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5}, true},
                {null, new byte[0], false},
                {new byte[0], null, false},
                {new byte[1], new byte[0], false},
                {new byte[0], new byte[1], false},
                {new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 6}, false},
                {new byte[]{1, 2, 3, 4, 6}, new byte[]{1, 2, 3, 4, 5}, false},
                {new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5, 6}, false},
                {new byte[]{1, 2, 3, 4, 5, 6}, new byte[]{1, 2, 3, 4, 5}, false},
                {new byte[]{Byte.MIN_VALUE, Byte.MAX_VALUE}, new byte[]{Byte.MAX_VALUE, Byte.MIN_VALUE}, false}
        };
    }

    @Test(dataProvider = "equalsTestCases")
    public void shouldImplementEqualityCorrectly(byte[] a, byte[] b, boolean equal) {
        assertThat(Bytes.equal(a, b)).isEqualTo(equal);
    }

    @DataProvider
    public Object[][] reverseTestCases() {
        byte[] bytesAsc = new byte[256];
        byte[] bytesDesc = new byte[256];
        int i = 0;
        for (int b = Byte.MIN_VALUE; b <= Byte.MAX_VALUE; ++b) {
            bytesAsc[i] = (byte) b;
            bytesDesc[256 - i - 1] = (byte) b;
            i++;
        }

        return new Object[][]{
                {new byte[0], new byte[0]},
                {new byte[]{42}, new byte[]{42}},
                {new byte[]{0, 1, 2, 3, 4}, new byte[]{4, 3, 2, 1, 0}},
                {new byte[]{0, 1, 2, 3, 4, 5}, new byte[]{5, 4, 3, 2, 1, 0}},
                {new byte[]{0, 1, 2, 2, 1, 0}, new byte[]{0, 1, 2, 2, 1, 0}},
                {bytesAsc, bytesDesc}
        };
    }

    @Test(dataProvider = "reverseTestCases")
    public void shouldReverseBytesCorrectly(byte[] forward, byte[] reverse) {
        assertThat(Bytes.reverse(forward.clone())).isEqualTo(reverse);
        assertThat(Bytes.reverse(reverse.clone())).isEqualTo(forward);
    }

    @Test
    public void shouldGenerateRandomDataOfTheRequestedSize() {
        for (int i = 0; i < 1000; ++i) {
            assertThat(Bytes.secureRandom(i)).hasSize(i);
        }
    }

    @DataProvider
    public Object[][] concat2ArgCases() {
        return new Object[][] {
                {new byte[0], new byte[0], new byte[0]},
                {new byte[]{42}, new byte[0], new byte[]{42}},
                {new byte[0], new byte[]{42}, new byte[]{42}},
                {new byte[]{42}, new byte[]{43}, new byte[]{42, 43}},
                {new byte[]{1,2,3}, new byte[]{4,5,6}, new byte[]{1,2,3,4,5,6}}
        };
    }

    @Test(dataProvider = "concat2ArgCases")
    public void shouldConcatenate2ByteArraysCorrectly(byte[] a, byte[] b, byte[] concat) {
        assertThat(Bytes.concat(a, b)).isEqualTo(concat);
    }

    @DataProvider
    public Object[][] concat3ArgCases() {
        return new Object[][] {
                {new byte[0], new byte[0], new byte[0], new byte[0]},
                {new byte[]{42}, new byte[0], new byte[0], new byte[]{42}},
                {new byte[0], new byte[]{42}, new byte[0], new byte[]{42}},
                {new byte[0], new byte[0], new byte[]{42}, new byte[]{42}},
                {new byte[]{42}, new byte[]{43}, new byte[0], new byte[]{42, 43}},
                {new byte[]{42}, new byte[0], new byte[]{43}, new byte[]{42, 43}},
                {new byte[0], new byte[]{42}, new byte[]{43}, new byte[]{42, 43}},
                {new byte[]{1,2,3}, new byte[]{4,5,6}, new byte[]{7,8,9}, new byte[]{1,2,3,4,5,6,7,8,9}}
        };
    }

    @Test(dataProvider = "concat3ArgCases")
    public void shouldConcatenate3ByteArraysCorrectly(byte[] a, byte[] b, byte[] c, byte[] concat) {
        assertThat(Bytes.concat(a, b, c)).isEqualTo(concat);
    }
}