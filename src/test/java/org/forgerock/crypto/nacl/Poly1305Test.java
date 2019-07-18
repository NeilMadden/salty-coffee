/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.crypto.nacl;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

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

    private static byte[] fromHex(String hex) {
        byte[] bytes = new byte[(hex.length() + 1) / 3];
        int i = 0;
        for (String hd : hex.split(":")) {
            bytes[i++] = (byte) (Integer.parseInt(hd, 16) & 0xFF);
        }
        return bytes;
    }

}