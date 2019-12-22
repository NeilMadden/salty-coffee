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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class HSalsa20 {

    private static final int[] OUTPUT_INDICES = { 0, 5, 10, 15, 6, 7, 8, 9 };

    static byte[] apply(byte[] key, byte[] nonce) {
        int[] state = Salsa20.initialState(key, nonce);
        Salsa20.rounds(state);
        ByteBuffer buffer = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        for (int i : OUTPUT_INDICES) {
            buffer.putInt(state[i]);
        }

        return buffer.array();
    }
}
