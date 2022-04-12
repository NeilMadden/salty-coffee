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

import static org.assertj.core.api.Assertions.assertThat;

public class ByteSliceTest {

    @Test
    public void shouldCaptureEntireArrayIfSpecified() {
        var array = new byte[]{ 42, 43, 44 };
        var slice = ByteSlice.of(array);
        assertThat(slice.toByteArray()).isEqualTo(array);
        assertThat(slice.length()).isEqualTo(3);
    }

    @Test
    public void shouldCaptureRestOfArray() {
        var array = new byte[]{ 42, 43, 44, 45, 46 };
        var slice = ByteSlice.of(array, 2);
        assertThat(slice.toByteArray()).containsExactly(44, 45, 46);
        assertThat(slice.length()).isEqualTo(3);
    }

    @Test
    public void shouldCaptureGivenSliceOfArray() {
        var array = new byte[]{ 42, 43, 44, 45, 46 };
        var slice = ByteSlice.of(array, 1, 3);
        assertThat(slice.toByteArray()).containsExactly(43, 44, 45);
        assertThat(slice.length()).isEqualTo(3);
    }

    @Test
    public void shouldCaptureGivenRangeOfArray() {
        var array = new byte[]{ 42, 43, 44, 45, 46 };
        var slice = ByteSlice.ofRange(array, 1, 3);
        assertThat(slice.toByteArray()).containsExactly(43, 44);
        assertThat(slice.length()).isEqualTo(2);
    }

    @Test
    public void shouldWipeCorrectSliceOfArray() {
        var array = new byte[]{ 42, 43, 44, 45, 46 };
        var slice = ByteSlice.ofRange(array, 1, 3);
        slice.wipe();
        assertThat(array).containsExactly(42, 0, 0, 45, 46);
    }
}