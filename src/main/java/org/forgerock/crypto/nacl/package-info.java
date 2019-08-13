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