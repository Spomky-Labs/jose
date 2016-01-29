How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [Signed JWT (JWS)](object/jws.md)
* [Encrypted JWT (JWE)](object/jwe.md)
* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)

To create these objects, this library provides factories.

* [JWS Factory](factory/jws.md)
* [JWE Factory](factory/jwe.md)
* [JWK Factory](factory/jwe.md)
 
Please note that there is no factory for the `JWKSet` object (a factory is useless as the object can be instatiate directly).

# The operations

## How To Add A Signature?

To add a signature on a `JWS` object, you will need to create:

* the `JWS` object itself,
* a key (`JWK` object),
* a `Signer` object with algorithm you want to use.

Example
-------

```php
use Jose\Factory\JWSFactory;
use Jose\Factory\KeyFactory;
use Jose\Factory\SignerFactory;

// We create our JWS object with claims
$jws = JWSFactory::createJWS([
   'iss' => 'https://my-authorization-server.com',
   'aud' => 'https://your-resource-server.com',
   'sub' => '0123456789',
   'exp' => 1456789018,
   'iat' => 1456780018,
   'nbf' => 1456780018,
]);

// We load two keys
$key1 = KeyFactory::createFromFile('/path/to/my/RSA/private.encrypted.key', 'Password');
$key2 = KeyFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// We create our Signer service and we declare the algorithms we want to use ('HS512' and 'RS512')
$signer = SignerFactory::createSigner(['HS512', 'RS512']);

// We add the first signature using our RSA key and algorithm RS512
$jws = $signer->addSignature(
   $jws,
   $key1,
   ['alg' => 'RS512']
);

// We add the second signature using our shared key and algorithm HS512
$jws = $signer->addSignature(
   $jws,
   $key2,
   ['alg' => 'HS512']
);

// Now our JWS object contains 2 signatures.
// We can convert each signature into compact or flattened JSON.
// We can convert the JWS into JSON with all signatures
$jws->toCompactJSON(0); // We convert the first signature (#0) into compact JSON
$jws->toCompactJSON(1); // We convert the second signature (#1) into flattened JSON
$jws->toJSON(); // We convert all signatures into JSON
```

### Important note

Please note that if a signature contains unprotected headers, it cannot be converted into Compact JSON Serialization mode.

### Detached payload

In some cases, you will need to detached the payload. This library supports `JWS` with detached payload.

Example
-------

```php
use Jose\Factory\JWSFactory;
use Jose\Factory\KeyFactory;
use Jose\Factory\SignerFactory;

// We create our JWS object with claims
// The method used is 'createJWSWithDetachedPayload'.
// The second argument will contain the encoded payload
$jws = JWSFactory::createJWSWithDetachedPayload(
   [
      'iss' => 'https://my-authorization-server.com',
      'aud' => 'https://your-resource-server.com',
      'sub' => '0123456789',
      'exp' => 1456789018,
      'iat' => 1456780018,
      'nbf' => 1456780018,
   ],
   $encoded_payload
);

// We load two keys
... See previous example

// We add a signature using our RSA key and algorithm RS512
// Please note that the method is now 'addSignatureWithDetachedPayload' and the third argument is the detached payload
$jws = $signer->addSignatureWithDetachedPayload(
   $jws,
   $key1,
   $detached_payload,
   ['alg' => 'RS512']
);

);

// Now our JWS object contain all signatures, but hte payload is empty.
// As in the previous example, the signatures can be converted into JSON (including compact and flattened).
// The payload will not be present.
```

## How To Add A Recipient (= encrypt)?

**To be written**

### Additional Authenticated Data

This library supports Additional Authenticated Data (AAD).

```php

```

### Important note

With this library, you can create encrypt an input using multiple recipients.
In this case, the Key Management Mode is determined according to the used algorithms.

You cannot create multiple recipients if the Key Management Mode are not compatible.
Hereafter, a table with algorithms and associated Key Management Mode.

| Algorithm \ Key Management Mode | Key Encryption | Key Wrapping | Direct Key Agreement | Key Agreement with Key Wrapping | Direct Encryption |
|---------------------------------|----------------|--------------|----------------------|---------------------------------|-------------------|
| dir                             |                |              |                      |                                 |        X          |
| A128KW                          |                |      X       |                      |                                 |                   |
| A192KW                          |                |      X       |                      |                                 |                   |
| A256KW                          |                |      X       |                      |                                 |                   |
| ECDH-ES                         |                |              |         X            |                                 |                   |
| ECDH-ES+A128KW                  |                |              |                      |                X                |                   |
| ECDH-ES+A192KW                  |                |              |                      |                X                |                   |
| ECDH-ES+A256KW                  |                |              |                      |                X                |                   |
| PBES2-HS256+A128KW              |                |      X       |                      |                                 |                   |
| PBES2-HS384+A192KW              |                |      X       |                      |                                 |                   |
| PBES2-HS512+A256KW              |                |      X       |                      |                                 |                   |
| RSA1_5                          |      X         |              |                      |                                 |                   |
| RSA-OAEP                        |      X         |              |                      |                                 |                   |
| RSA-OAEP-256                    |      X         |              |                      |                                 |                   |
| A128GCMKW                       |                |      X       |                      |                                 |                   |
| A192GCMKW                       |                |      X       |                      |                                 |                   |
| A256GCMKW                       |                |      X       |                      |                                 |                   |

And a compatibility table between Key Management Modes:

|        Key Management Mode      | Key Encryption | Key Wrapping | Direct Key Agreement | Key Agreement with Key Wrapping | Direct Encryption |
|---------------------------------|----------------|--------------|----------------------|---------------------------------|-------------------|
| Key Encryption                  |     YES        |     YES      |        NO *          |            YES                  |       NO *      |
| Key Wrapping                    |     YES        |     YES      |        NO *          |            YES                  |       NO *      |
| Direct Key Agreement            |     NO *       |     NO *     |        YES           |            NO *                 |       NO          |
| Key Agreement with Key Wrapping |     YES        |     YES      |        NO *          |            YES                  |       NO *      |
| Direct Encryption               |     NO *       |     NO *     |        NO            |            NO *                 |       YES         |

*: Compatibility is possible only if the algorithm for the first recipient is a `Direct Key Agreement` or a `Direct Encryption` algorithm and there is no other recipient using the same algorithms, otherwise it is not possible

### Important note

Please note that if a recipient contains unprotected headers or the `JWE` contains unprotected shared headers, it cannot be converted into Compact JSON Serialization mode.

## How To Load?

**To be written**

