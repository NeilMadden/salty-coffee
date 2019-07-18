/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

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
