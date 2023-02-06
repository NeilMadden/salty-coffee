[![License](https://img.shields.io/:license-Apache2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://github.com/NeilMadden/salty-coffee/actions/workflows/maven.yml/badge.svg)](https://github.com/NeilMadden/salty-coffee/actions/workflows/maven.yml)

# Salty Coffee

A pure-Java implementation of the [NaCl](https://nacl.cr.yp.to) cryptographic library.

Currently, this requires Java 11+ but has zero additional dependencies (other than for testing).
Since version 1.0.4, the library includes a JPMS module declaration. Android support is known to be patchy.

Licensed under the [Apache 2.0 license](LICENSE.txt).

## Has this library been audited?

Many people are understandably wary of using a cryptographic library that has not been audited by
professional cryptographers. Salty Coffee **has not yet been independently audited**.

However, very little of the cryptographic code in Salty Coffee is new. The implementations of Ed25519
and Poly1305 are taken directly from [Google Tink](https://github.com/google/tink), which is written and
maintained by experts. I regularly update this code to bring in the latest bug fixes from upstream
(last checked April 2022). Small alterations are made to remove unused methods, reduce the visibility
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
    <version>1.1.1</version>
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

This uses X25519 key agreement, followed by XSalsa20-Poly1305.

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
byte[] seed = Bytes.secureRandom(32);
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
SecretKey authKey = Crypto.authKeyGen();
byte[] tag = Crypto.auth(authKey, msg);
boolean valid = Crypto.authVerify(authKey, msg, tag);
```

The algorithm is `HMAC-SHA512-256` (i.e., the first 256 bits of HMAC with SHA-512).

### Authenticating multiple fields of data

If you need to authenticate multiple fields of data then the `Crypto.authMulti` method can authenticate an arbitrary
number of data packets:
```java
List<byte[]> blocks = List.of(...);
SecretKey authKey = Crypto.authKeyGen();
byte[] tag = Crypto.authMulti(authKey, blocks);
boolean valid = Crypto.authVerifyMulti(authKey, blocks, tag);
```
The tag will only validate if the exact same blocks of data are presented in exactly the same order. Any alteration to
any block, or any addition, removal, or reordering of blocks will result in validation failure.

The algorithm is based on `HMAC-SHA512-256` in a cascade construction, as described in
[Multiple input MACs](https://neilmadden.blog/2021/10/27/multiple-input-macs/).

## Hashing

```java
byte[] hash = Crypto.hash(data);
```
This is SHA-512.

## Random bytes

```java
byte[] random = Bytes.secureRandom(16); // Returns a 16-byte buffer
```

This will uses the best-quality non-blocking secure random source it can find. It goes out of its way to avoid
Java's SHA1PRNG. By default on UNIX it will read from `/dev/urandom`, while on Windows it will use `CryptGenRandom()`.
This is a best-effort basis, and configuration of `java.security` may change the behaviour.

## Key derivation

Since version 1.0.5, Salty Coffee provides two methods for deriving independent sub-keys from some high-entropy input
key material. The input key material can either be a uniformly-random secret key, such as that returned from 
`Crypto.kdfKeyGen()`, or a high-entropy, but *not* uniformly-random source of key material such as a *long* random
string or the raw output of a key agreement process like Diffie-Hellman.

**Warning:** These key derivation functions are *not* suitable for use with low-entropy inputs like passwords. A proper
password-based KDF may be added in a future release.

### Context binding

Both key derivation functions (KDFs) support *binding* the derived keys to some *context*, describing how the keys are 
to be used. Any change in the context will result in completely different key material being generated, with very high
probability. This can be used to allow the same root key to be safely used for different purposes, by ensuring that
distinct sub-keys are derived for each context. Examples of data to include in the context are:

 * Identities of parties involved in a communication, such as user names.
 * Public keys or certificates of those parties.
 * An identifier for the application or protocol the keys will be used for, along with any algorithm names or 
   parameters.

The context should be unambiguously encoded, for example using a format like JSON, CBOR, or ProtoBufs, or simply
prefixing any variable-length fields with a fixed-length representation of their length.

NIST [SP 800-56C: Recommendations for Key-Derivation Methods in Key-Establishment Schemes](https://doi.org/10.6028/NIST.SP.800-56Cr2)
has further details of what should be included in the context argument and recommendations for formatting.

The KDF implementation in Salty Coffee is [HKDF](https://www.rfc-editor.org/rfc/rfc5869) using HMAC-SHA-512.

### Key derivation from a high-entropy uniform random key

```java
SecretKey rootKey = Crypto.kdfKeyGen();
byte[] context = "My Test Application".getBytes("UTF-8");
byte[] keyMaterial = Crypto.kdfDeriveKeyFromKey(rootKey, context, 64);
SecretKey authKey = Crypto.authKey(ByteSlice.ofRange(keyMaterial, 0, 32));
SecretKey encKey = Subtle.streamXSalsa20Key(ByteSlice.ofRange(keyMaterial, 32, 64));
```

### Key derivation from high-entropy non-uniform input key material

```java
byte[] inputKeyMaterial = Subtle.scalarMultiplication(privKey, pubKey);
byte[] salt = Bytes.secureRandom(16);
byte[] context = "My Test Application".getBytes("UTF-8");
byte[] keyMaterial = Crypto.kdfDeriveFromInputKeyMaterial(saly, inputKeyMaterial, context, 64);
```
The `context` argument is as for `Crypto.kdfDeriveFromKey`. The `salt` argument, if specified, should ideally be a
uniformly random byte string from a high entropy source. The purpose of the `salt` argument is to improve the
randomness extraction from the input key material. The `salt` should come from a trusted source, and must not be
under attacker control. For example, if the salt is sent in a message then it *must* be authenticated before being used
in the KDF, for example by signing the salt using `Crypto.sign` and verifying the signature before calling the KDF.
The salt value can be public and can be fixed for a particular use of the KDF. For example, even a fixed string as the
salt value can provide *domain separation* between different uses of the KDF for different applications. If a `null`
or empty salt value is specified, then a fixed 64-byte all-zero salt value is used instead.

# Low-level primitives

Salty Coffee now exposes some low-level cryptographic primitives via the `software.pando.crypto.nacl.Subtle` class.
As the name suggests, these utilities have complex and subtle security properties, and are intended for use by experts.
You are **strongly recommended** to use the facilities in the main `Crypto` class in preference to these primitives,
but they are provided for compatibility with existing protocols and applications.

## Scalar multiplication

The `Subtle.scalarMultiplication()` method provides access to the raw X25519 key agreement function. This provides
elliptic curve scalar multiplication between a Curve 25519 public point and a secret scalar value.

**Warning:** It is not safe to use the output of this function directly as a cryptographic key. Use
`Crypto.kdfDeriveFromInputKeyMaterial` to convert the output of this function into one or more cryptographic keys, or
use `CryptoBox` for a complete public key authenticated encryption solution.

## Stream cipher

A raw *unauthenticated* stream cipher is provided by `Subtle.streamXSalsa20()`. This method implements the XSalsa20
stream cipher.

**Warning:** An attacker can arbitrarily tamper with encrypted data produced by this stream cipher. You should prefer to
use `SecretBox` unless you really know what you are doing.

```java
byte[] data = "Hello, Salty!".getBytes("UTF-8");
SecretKey key = Subtle.streamXSalsa20KeyGen();
byte[] nonce = Subtle.streamXSalsa20(key)
        .process(ByteSlice.of(data))
        .nonce();
// data is now encrypted
Subtle.streamXSalsa20(key, nonce)
        .process(ByteSlice.of(data));
// data is now decrypted again
assert new String(data, "UTF-8").equals("Hello, Salty!");
```
