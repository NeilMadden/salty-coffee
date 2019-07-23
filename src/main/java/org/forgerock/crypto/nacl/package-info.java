/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

/**
 * Implementation of the <a href="https://nacl.cr.yp.to">NaCl</a>
 * cryptographic library in pure Java. Available functionality:
 * <ul>
 *     <li>{@link org.forgerock.crypto.nacl.CryptoBox} - public key authenticated encryption.</li>
 *     <li>{@link org.forgerock.crypto.nacl.SecretBox} - secret key authenticated encryption.</li>
 *     <li>{@link org.forgerock.crypto.nacl.Crypto#auth(javax.crypto.SecretKey, byte[])} - secret key message
 *     authentication.</li>
 *     <li>{@link org.forgerock.crypto.nacl.Crypto#sign(java.security.PrivateKey, byte[])} - public key signatures.</li>
 * </ul>
 */
package org.forgerock.crypto.nacl;