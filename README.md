[![License](https://img.shields.io/:license-Apache2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://github.com/NeilMadden/salty-coffee/actions/workflows/maven.yml/badge.svg)](https://github.com/NeilMadden/salty-coffee/actions/workflows/maven.yml)

# Salty Coffee

A pure-Java implementation of the [NaCl](https://nacl.cr.yp.to) cryptographic library.

Currently, this requires Java 11+ but has zero additional dependencies (other than for testing).
Since version 1.0.4, the library includes a JPMS module declaration.

Licensed under the [Apache 2.0 license](LICENSE.txt).

## Has this library been audited?

Many people are understandably wary of using a cryptographic library that has not been audited by
professional cryptographers. Salty Coffee **has not yet been independently audited**.

However, very little of the cryptographic code in Salty Coffee is new. The implementations of Ed25519
and Poly1305 are taken directly from [Google Tink](https://github.com/google/tink), which is written and
maintained by experts. I regularly update this code to bring in the latest bug fixes from upstream
(last checked July 2021). Small alterations are made to remove unused methods, reduce the visibility
of other methods, inline methods from auxillary classes, and add small wrapper utilities. No changes are made to the 
core cryptographic implementations.

For SHA-512 and X25519, Salty Coffee uses the implementations from the JDK, which may be influenced by the 
configuration of the JDK installation.

The only entirely novel cryptographic code in Salty Coffee is the implementation of XSalsa20 as this is not present 
in either Tink or the JDK. Thankfully, Salsa20 is perhaps one of the simplest cryptographic algorithms to implement 
securely. Again, it must be stressed that this code has **not yet been audited**. 

## Installation

Artifacts are available from Maven Central:

```xml
<dependency>
    <groupId>software.pando.crypto</groupId>
    <artifactId>salty-coffee</artifactId>
    <version>1.0.4</version>
</dependency>
```

# Usage

```java
import software.pando.crypto.nacl.*;
```

## Secret Key Authenticated Encryption

```java
SecretKey key = SecretBox.key();
SecretBox box = SecretBox.encrypt(key, "Hello, World!"); // can also pass byte[]
```

This uses the XSalsa20-Poly1305 authenticated stream cipher, which can be used to encrypt and authenticate an essentially
unlimited amount of data before the key needs to be rotated.

This can then be serialized to/from a URL-safe string:

```java
String str = box.toString();
SecretBox box2 = SecretBox.fromString(str);
```

or in a binary format:
```java
try (OutputStream out = ...) {
    box.writeTo(out);
}
try (InputStream in = ...) {
    SecretBox box2 = SecretBox.readFrom(in);
}
```
You can then decrypt and verify using either:
```java
byte[] decrypted = box.decrypt(key);
String decrypted = box.decryptToString(key); // Assumes UTF-8
```

## Public Key Authenticated Encryption

```java
KeyPair aliceKeys = CryptoBox.keyPair();
KeyPair bobKeys = CryptoBox.keyPair();

CryptoBox box = CryptoBox.encrypt(aliceKeys.getPrivate(), bobKeys.getPublic(), "Hello, World!");
String msg = box.decryptToString(bobKeys.getPrivate(), aliceKeys.getPublic());
```

This uses X25519 key agreement, followed by XSalsa20-Poly1305. We use the X25519 implementation in Java 11, but provide
our own implementations of XSalsa20 and Poly1305 (adapted from libsodium sources).

Unlike most public key encryption schemes, NaCl's CryptoBox is *authenticated encryption*: if the message decrypts then
it must have come from Alice. This avoids the need for nested signed-then-encrypted formats like in JWT.

Just as with `SecretBox`, you can serialize to/from string and binary formats. In fact, the two formats are identical:

```java
CryptoBox box = CryptoBox.encrypt(aliceKeys.getPrivate(), bobKeys.getPublic(), "Hello, World!");
SecretBox sb = SecretBox.fromString(box.toString());

Key agreedKey = CryptoBox.agree(aliceKeys.getPrivate(), bobKeys.getPublic());
sb.decrypt(agreedKey);
```

### Keypairs from a seed

You can deterministically generate key-pairs from a 32-byte "seed" value. The same key-pair will be generated for the same
seed:

```java
byte[] seed = ...;
KeyPair keyPair = CryptoBox.seedKeyPair(seed);
```

**NOTE**: the seed should be treated as a secret key and generated and stored securely.

## Public key signatures

You can sign a message to produce a public key signature using:

```java
KeyPair keyPair = Crypto.signingKeyPair();
byte[] sig = Crypto.sign(keyPair.getPrivate(), msg);
```

The signature can then be verified by anybody with the public key:

```java
boolean valid = Crypto.signVerify(keyPair.getPublic(), msg, sig);
```

The algorithm is Ed25519 using SHA-512. The Ed25519 implementation is extracted from
Google's Tink library. Salty Coffee currently only supports detached signatures.

You can use `Crypto.signingPrivateKey(byte[])` and `Crypto.signingPublicKey(byte[])` to reconstruct
private and public Ed25519 keys from raw binary values. As for CryptoBox key pairs, you can also use
`Crypto.seedSigningKeyPair(byte[])` to deterministically derive a signing key pair from a 32-byte
secret seed value.

## Secret key authentication

You can perform authentication (MAC) without encryption:
```java
byte[] msg = ...;
Key authKey = Crypto.authKey();
byte[] tag = Crypto.auth(authKey, msg);
boolean valid = Crypto.authVerify(authKey, msg, tag);
```

The algorithm is HMAC-SHA512-256 (i.e., the first 256 bits of HMAC with SHA-512).

## Hashing

```java
byte[] hash = Crypto.hash(data);
```
This uses SHA-512.

## Random bytes

```java
byte[] random = Bytes.secureRandom(16); // Returns a 16-byte buffer
```

This will uses the best-quality non-blocking secure random source it can find. It goes out of its way to avoid
Java's SHA1PRNG. By default on UNIX it will read from `/dev/urandom`, while on Windows it will use `CryptGenRandom()`.
This is a best-effort basis, and configuration of `java.security` may change the behaviour.
