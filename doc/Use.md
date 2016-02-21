How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [Signed JWT (JWS)](object/jws.md)
* [Encrypted JWT (JWE)](object/jwe.md)
* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)

# The operations

## How To Add A Signature?

To add a signature on a `JWS` object, you will need to create:

* the `JWS` object itself,
* a private or symmetric key (`JWK` object),
* a `Signer` object with algorithm you want to use.

Example
-------

```php
use Jose\Factory\JWSFactory;
use Jose\Factory\JWKFactory;
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
$key1 = JWKFactory::createFromFile('/path/to/my/RSA/private.encrypted.key', 'Password');
$key2 = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// We create our Signer service and we declare the algorithms we want to use ('HS512' and 'RS512')
$signer = SignerFactory::createSigner(['HS512', 'RS512']);

// We add the first signature using our RSA key and algorithm RS512
$signer->addSignature(
   $jws,
   $key1,
   ['alg' => 'RS512']
);

// We add the second signature using our shared key and algorithm HS512
$signer->addSignature(
   $jws,
   $key2,
   ['alg' => 'HS512']
);

// Now our JWS object contains 2 signatures.
// We can convert each signature into compact or flattened JSON.
// We can convert the JWS into JSON with all signatures
$jws->toCompactJSON(0); // We convert the first signature (#0) into compact JSON
$jws->toFlattenedJSON(1); // We convert the second signature (#1) into flattened JSON
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
use Jose\Factory\JWKFactory;
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
$signer->addSignatureWithDetachedPayload(
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

To add a recipient on a `JWE` object, you will need to create:

* the `JWE` object itself,
* a public or symmetric key (`JWK` object),
* if you use `ECDH-ES` based algorithms, a private key (`JWK` object),
* an `Encrypter` object with algorithm you want to use.

Example
-------

```php
use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\EncrypterFactory;

// We create our JWE object with claims
$jws = JWEFactory::createJWE(
    'My very important information',
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);

// We load the recipient RSA public key
$recipient_key = JWKFactory::createFromFile('/path/to/the/recipient/public.key');

// We create our Encrypter service and we declare the algorithms we want to use ('A256CBC-HS512' and 'RSA-OAEP-256')
$encrypter = EncrypterFactory::createEncrypter(['A256CBC-HS512', 'RSA-OAEP-256']);

// We add a recipient using our RSA key
$encrypter->addRecipient(
   $jwe,           // The JWE object
   $recipient_key, // The recipient's key
);


// Now our JWE object contains the encrypted payload and 1 recipient.
// We can convert each recipient into compact or flattened JSON.
// We can convert the JWE into JSON with all signatures
$jwe->toCompactJSON(0); // We convert the recipient (#0) into compact JSON
$jwe->toFlattenedJSON(1); // We convert the recipient (#0) into flattened JSON
$jwe->toJSON(); // We convert all recipients into JSON
```

### Additional Authenticated Data

This library supports Additional Authenticated Data (AAD).

```php
$jws = JWEFactory::createJWE(
    'My very important information',
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ],
    [
        'shared unprotected header' => 'value',
    ],
    'This is an AAD'
);
```

Please note that when a JWE object contains an AAD or unprotected headers (shared or per recipient), the JWE cannot be
converted into compact JSON.

### Encryption using `ECDH-ES` base algorithms

`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and `ECDH-ES+A256KW` key encryption algorithms require a private key besides the recipient public key to be used.

Example
-------

```php
use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\EncrypterFactory;

// We create an ephemeral private key
// Supported curves are 'P-256' 'P-384' and 'P-521'
$private_key = JWKFactory::createRandomECPrivateKey('P-256');


// We create our JWE object with claims
$jws = JWEFactory::createJWE(
    'My very important information',
    [
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);

// We load the recipient EC public key
$recipient_key = JWKFactory::createFromFile('/path/to/the/recipient/ec_p_256_public.key');

// We create our Encrypter service and we declare the algorithms we want to use ('A256CBC-HS512' and 'ECDH-ES+A128KW')
$encrypter = EncrypterFactory::createEncrypter(['A256CBC-HS512', 'ECDH-ES+A128KW']);

// We add a recipient using our RSA key and algorithm ECDH-ES+A128KW
$encrypter->addRecipient(
   $jwe,                       // The JWE object
   $recipient_key,             // The recipient's key
   $private_key,               // The sender private key (our ephemeral key)
   ['alg' => 'ECDH-ES+A128KW'] // The recipient' headers (we only declare the algorithm used for key encryption)
);


// Now our JWE object contains the encrypted payload and 1 recipient.
// We can convert each recipient into compact or flattened JSON.
// We can convert the JWE into JSON with all signatures
$jwe->toCompactJSON(0); // We convert the recipient (#0) into compact JSON
$jwe->toFlattenedJSON(1); // We convert the recipient (#0) into flattened JSON
$jwe->toJSON(); // We convert all recipients into JSON
```

### Multiple recipients support

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
| ECDH-ES *                       |                |              |         X            |                                 |                   |
| ECDH-ES+A128KW *                |                |              |                      |                X                |                   |
| ECDH-ES+A192KW *                |                |              |                      |                X                |                   |
| ECDH-ES+A256KW *                |                |              |                      |                X                |                   |
| PBES2-HS256+A128KW *            |                |      X       |                      |                                 |                   |
| PBES2-HS384+A192KW *            |                |      X       |                      |                                 |                   |
| PBES2-HS512+A256KW *            |                |      X       |                      |                                 |                   |
| RSA1_5                          |      X         |              |                      |                                 |                   |
| RSA-OAEP                        |      X         |              |                      |                                 |                   |
| RSA-OAEP-256                    |      X         |              |                      |                                 |                   |
| A128GCMKW *                     |                |      X       |                      |                                 |                   |
| A192GCMKW *                     |                |      X       |                      |                                 |                   |
| A256GCMKW *                     |                |      X       |                      |                                 |                   |


And a compatibility table between Key Management Modes:

|        Key Management Mode      | Key Encryption | Key Wrapping | Direct Key Agreement | Key Agreement with Key Wrapping | Direct Encryption |
|---------------------------------|----------------|--------------|----------------------|---------------------------------|-------------------|
| Key Encryption                  |     YES        |     YES      |        NO **         |            YES                  |       NO *      |
| Key Wrapping                    |     YES        |     YES      |        NO **         |            YES                  |       NO *      |
| Direct Key Agreement            |     NO **      |     NO **    |        YES           |            NO **                |       NO          |
| Key Agreement with Key Wrapping |     YES        |     YES      |        NO **         |            YES                  |       NO *      |
| Direct Encryption               |     NO **      |     NO **    |        NO            |            NO **                |       YES         |

`*`: As these algorithms add additional header information, you must indicate that you want to create a JWE with multiple recipients.
`**`: Compatibility is possible only if the algorithm for the first recipient is a `Direct Key Agreement` or a `Direct Encryption` algorithm and there is no other recipient using the same algorithms, otherwise it is not possible

## How To Load?

This library provides a simple JWT loader. This loader will return a JWS or JWE object depending on the input.
The loader is able to load compact JSON, flattened JSON or JSON representation.

```php
use Jose\Loader;

$input = 'eyJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE0NTE0NjkwMTcsImlhdCI6MTQ1MTQ2OTAxNywiZXhwIjoxNDUxNDcyNjE3LCJpc3MiOiJNZSIsImF1ZCI6IllvdSIsInN1YiI6Ik15IGZyaWVuZCJ9.mplHfnyXzUdlEkPmykForVM0FstqgiihfDRTd2Zd09j6CZzANBJbZNbisLerjO3lR9waRlYvhnZu_ewIAahDwmVTfpSeKKABbAyoTHXTH2WLgMPLtOAsoausUf584eAAj_kyldIOV8a83Qz1NztZHVD3DbGTiCN0BOj-qnc65yQmEDEYK5cxG1xC22YK5aohZ3xm8ixwNZpxYr8cNOkauASYjPGODbHqY_gjQ-aKA21kxbYgwM6mDYSc3QRej1_3m6bD3jKPsK4jv3yzosVMEXOparf4sEb8q_zCPMDJAJgZZ8VICwJdgYnJkQuIutS-w3_iT-riKl8fkgmJezQVkg';

// We load the input
$jwt = Loader::load($input);

// The variable $result a valid JWSInterface object.
```

At this stage, no verification or decryption has been performed.

* If the loaded input is a JWS, you MUST verify it
* If the loaded input is a JWE, you MUST decrypt it.

## How to verify a JWS?

** To be written **

## How to decrypt a JWE?

** To be written **
