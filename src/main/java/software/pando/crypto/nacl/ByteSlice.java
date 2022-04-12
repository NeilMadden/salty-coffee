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

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a slice of a byte array, represented as an offset and a length into that array.
 */
public final class ByteSlice {
    final byte[] array;
    final int offset;
    final int length;

    private ByteSlice(byte[] array, int offset, int length) {
        this.array = Objects.requireNonNull(array, "array");
        this.offset = Objects.checkFromIndexSize(offset, length, array.length);
        this.length = length;
    }

    /**
     * Converts the slice to a byte array. The returned array is always a copy of the underlying slice.
     *
     * @return a byte array copy of this slice.
     */
    public byte[] toByteArray() {
        return Arrays.copyOfRange(array, offset, offset + length);
    }

    /**
     * The number of bytes in the slice.
     *
     * @return the length of the slice, in bytes.
     */
    public int length() {
        return length;
    }

    void wipe() {
        Arrays.fill(array, offset, offset + length, (byte) 0);
    }

    /**
     * Static factory method for constructing a slice from an input array. This method does not copy the array, so any
     * changes subsequently made to the array will be reflected in the contents of the slice, and vice versa. Use
     * {@code array.clone()} if you wish to make the slice independent of the array.
     *
     * @param array the input byte array.
     * @param offset the offset into the array at which to start the slice. This must be between 0 and the length of
     *               the array.
     * @param length the length of the slice. The length of the array must be at least offset+length bytes long.
     * @return the constructed byte slice.
     * @throws NullPointerException if the array is null.
     * @throws IndexOutOfBoundsException if the offset or length are outside of the bounds of the provided array.
     */
    public static ByteSlice of(byte[] array, int offset, int length) {
        return new ByteSlice(array, offset, length);
    }

    /**
     * Static factory method for constructing a slice from an input array. This method does not copy the array, so any
     * changes subsequently made to the array will be reflected in the contents of the slice, and vice versa. Use
     * {@code array.clone()} if you wish to make the slice independent of the array.
     *
     * @param array the input byte array.
     * @param from the offset into the array at which to start the slice (inclusive). This must be between 0 and less
     *             than the length of the array.
     * @param to the offset into the array at which to end the slice (exclusive).
     * @return the constructed byte slice.
     * @throws NullPointerException if the array is null.
     * @throws IndexOutOfBoundsException if the offset or length are outside of the bounds of the provided array.
     */
    public static ByteSlice ofRange(byte[] array, int from, int to) {
        Objects.checkFromToIndex(from, to, array.length);
        return of(array, from, to - from);
    }

    /**
     * Static factory method for constructing a slice from an input array. This method does not copy the array, so any
     * changes subsequently made to the array will be reflected in the contents of the slice, and vice versa. Use
     * {@code array.clone()} if you wish to make the slice independent of the array.
     *
     * @param array the input byte array.
     * @param offset the offset into the array at which to start the slice. This must be between 0 and the length of
     *               the array. The slice will cover the array from the given offset until the end of the array.
     * @return the constructed byte slice.
     * @throws NullPointerException if the array is null.
     * @throws IndexOutOfBoundsException if the offset is outside of the bounds of the provided array.
     */
    public static ByteSlice of(byte[] array, int offset) {
        return of(array, offset, array.length - offset);
    }

    /**
     * Static factory method for constructing a slice from an input array. This method does not copy the array, so any
     * changes subsequently made to the array will be reflected in the contents of the slice, and vice versa. Use
     * {@code array.clone()} if you wish to make the slice independent of the array. The constructed slice will cover
     * the entire contents of the array.
     *
     * @param array the input byte array.
     * @return the constructed byte slice.
     * @throws NullPointerException if the array is null.
     */
    public static ByteSlice of(byte[] array) {
        return of(array, 0);
    }
}
