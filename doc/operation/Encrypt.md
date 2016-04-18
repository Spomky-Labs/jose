Encrypt a message
=================

This library provides several ways to encrypt a message (e.g. a text or a JWS).
In most cases, you will need to sign with only one key and export in JSON Compact Serialization Mode (a five parts Base64 encoded string separated with dots).

# The Easiest Way

A JWEFactory is available to ease all operations. We recommend to use it to create Compact JWE.
The minimum requirement is:

* the message to encrypt,
* the key encryption and the content encryption algorithms used to encrypt,
* the recipient key: a public or symmetric key ([`JWK` object](../object/jwk.md)) depending on the key encryption algorithm.

Example
-------

```php
use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;

// We create our key object (JWK) using a public RSA key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__.'/../tests/Unit/Keys/RSA/public.key',
    null,
    [
        'kid' => 'My Public RSA key',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

// We want to encrypt a very important message
$message = 'Today, 8:00PM, train station.'
$jwe = JWEFactory::createJWEToCompactJSON(
    $message,                    // The message to encrypt
    $key,                        // The key of the recipient
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);
```

Now the variable `$jwe` contains a string that represents our JWE.

# The JWEFactory In Details

## Flattened JWE with/without Detached Payload

The flattened JWE JSON Serialization syntax is based upon the general syntax but flattens it, optimizing it for the single digital signature/MAC case.
You can produce such JWE the same way as Compact JWE.

The methods to use are `createJWEToFlattenedJSON` but also allow you to define unprotected headers and Additional Authenticated Data.

## Multiple Recipients

*To be completed*

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
| Key Encryption                  |     YES        |     YES      |        NO            |            YES                  |       NO          |
| Key Wrapping                    |     YES        |     YES      |        NO            |            YES                  |       NO          |
| Direct Key Agreement            |     NO         |     NO       |        YES           |            NO                   |       NO          |
| Key Agreement with Key Wrapping |     YES        |     YES      |        NO            |            YES                  |       NO          |
| Direct Encryption               |     NO         |     NO       |        NO            |            NO                   |       YES         |
