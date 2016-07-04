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

## Flattened JWE

The flattened JWE JSON Serialization syntax is based upon the general syntax but flattens it, optimizing it for the single digital signature/MAC case.
You can produce such JWE the same way as Compact JWE.

The method to use is `createJWEToFlattenedJSON`. This method allows you to define unprotected headers and Additional Authenticated Data.

## Multiple Recipients

Compact and Flattened JWE allow only one recipient. You may need to produce JWE with multiple recipients.

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWEFactory;

// We load the key of the recipient #1. It will be used to encrypt with the algorithm RSA-OAEP-256
$key1 = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/recipient#1.public.key',
    null,
    [
        'kid' => 'Recipient #1 Public RSA key',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

// We load the second key to sign using algorithm A256GCMKW
$key2 = JWKFactory::createFromValues(
    [
        'kty' => 'oct',
        'kid' => 'Recipient #2 Shared key',
        'use' => 'enc',
        'alg' => 'A256GCMKW',
        'k'   => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
    ]
);

// We want to encrypt the following massage
$message = 'Today, 8:00PM, train station.'

// We have to create a JWE class using the JWEFactory.
// The payload of this object contains our message.
$jwe = JWEFactory::createJWE(
    $message,                     // The payload
    [                             // The shared protected header
        'enc' => 'A128CBC-HS256', // We encrypt the payload using the content encryption algorithm A128CBC-HS256
        'zip' => 'DEF',           // We want to compress the payload before encryption (not mandatory, but useful for a large payload
    ],
    [                             // The shared unprotected header
        'other' => 'This is an unprotected payload for all recipients',
    ]
);

// We add information to create the first recipient 
$jwe = $jwe->addRecipientInformation(
    key1,                        // The recipient #1 key
    [                            // The recipient #1 unprotected header
        'alg' => 'RSA-OAEP-256',
    ]
);

// Then the information for the second signature
$jwe = $jwe->addRecipientInformation(
    key2,                        // The recipient #2 key
    [                            // The recipient #2 unprotected header
        'alg' => 'A256GCMKW',
    ]
);
```

Now, the variable `$jwe` contains an object that implements `Jose\Object\JWEInterface` and contain information to encrypt the payload and the content encryption key for all recipients.
It is important to note that nothing is encrypted at this moment.

We need to create a `Encrypter` object that will done this step.

```php
use Jose\Encrypter;

// We create a Encrypter object with the key encryption and content encryption algorithms we want to use
$encrypter = Encrypter::createEncrypter(
    ['RSA-OAEP-256', 'A256GCMKW'], // The Key Encryption Algorithms to be used
    ['A128CBC-HS256'],             // The Content Encryption Algorithms to be used
    ['DEF']                        // The Compression Methods to be used
);

// Then we encrypt
$encrypter->encrypt($jwe);
```

Now you can export it into the JSON General Serialization Mode:

```php
$jwe->toJSON();
```

You can also get each encryption into Flattened Serialization Mode:

```php
// The first signature into Flattened Serialization Mode
$jwe->toFlattenedJSON(0);

// The second one into Flattened Serialization Mode
$jwe->toFlattenedJSON(1);
```

It is not possible to export into Compact Serialization Mode as unprotected headers (shared and per recipient) have been defined.

### Key Management Modes

Each Key Encryption Algorithm has its own Key Management Mode.

You cannot create a JWE with multiple recipients if the Key Management Modes are not compatible.
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
| Direct Key Agreement            |     NO         |     NO       |        NO            |            NO                   |       NO          |
| Key Agreement with Key Wrapping |     YES        |     YES      |        NO            |            NO                   |       NO          |
| Direct Encryption               |     NO         |     NO       |        NO            |            NO                   |       NO          |

If you try to mix incompatible Key Management Mode, an error will be thrown by the encrypter.

### Additional Authenticated Data

This library supports Additional Authenticated Data (AAD).

```php
$jws = JWEFactory::createJWE(
    $message,                     // The payload
    [                             // The shared protected header
        'enc' => 'A128CBC-HS256', // We encrypt the payload using the content encryption algorithm A128CBC-HS256
        'zip' => 'DEF',           // We want to compress the payload before encryption (not mandatory, but useful for a large payload
    ],
    [                             // The shared unprotected header
        'other' => 'This is an unprotected payload for all recipients',
    ],                            // The Additional Authenticated Data
    'This is an AAD'
);
```

Please note that when a JWE object contains an AAD, it cannot be converted into Compact JSON.

## Algorithms and Parameters

The key encryption algorithms `PBES2-HS256+A128KW` `PBES2-HS384+A192KW` and `PBES2-HS512+A256KW` are instantiated using their default values:
* Salt size: 512 bits (64 bytes)
* Iterations: 4096

These values may not fit on your needs. Let say you want to use a 4096 bits (512 bytes) salt and 100000 iterations.
To do so, you just have to pass an instance of the algorithm with that parameters to the `Encrypter`.


```php
use Jose\Encrypter;
use Jose\Algorithm\KeyEncryption\PBES2HS256A128KW;

$encrypter = Encrypter::createEncrypter(
    [
        new PBES2HS256A128KW(512, 100000), // The Key Encryption algorithm with a 4096 bits (512 bytes) salt and 100000 iterations
    ],
    ['A128CBC-HS256'],             // The Content Encryption Algorithms to be used
);
```
