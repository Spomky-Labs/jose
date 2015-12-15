How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)
* The Jose:
    * [JWT](object/jwt.md)
    * [JWS](object/jws.md)
    * [JWE](object/jwe.md)
* The instructions:
    * [Signature instruction](object/signature_instruction.md)
    * [Encryption instruction](object/encryption_instruction.md)

# The operations

Depending on operations you want to perform, you have to initialize required components first.

## How To Sign

### Initialize components

If you want to sign data, you must initialize:

* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The signer itself](component/signer.md)

### Create a JWS

First, you must create a [signature instruction](object/signature_instruction.md) for each signature you want to create:

```php
use Jose\SignatureInstruction;

$instruction1 = new SignatureInstruction();
$instruction1->setProtectedHeader(['alg'=>'HS512'])
    ->setKey($my_first_key);
$instruction2 = new SignatureInstruction();
$instruction2->setProtectedHeader(['alg'=>'ES384'])
    ->setUnprotectedHeader('foo'=>'bar')
    ->setKey($my_second_key);
```

Then, you can sign your input:

```php
use Jose\JSONSerializationModes;
$input = 'The input to sign';
$instructions = [$instruction1, $instruction2];

$output = $signer->sign($input, $instructions, JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
```

### Output

The supported serialization modes can be found in [the Compact Serialization mode page](OutputModes.md).

The output depends on the output format you set and the number of instructions. It could be:

| Output Mode \ Number of instruction |   1    |        2+        |
|-------------------------------------|--------|------------------|
| Compact JSON Serialization          | string | array of strings |
| Flattened JSON Serialization        | string | array of strings |
| JSON Serialization                  | string | string           |


### Detached payload

In some cases, you will need to detached the payload. This library is able to perform this task for you.

```php
$output = $signer->sign($input, $instructions, JSONSerializationModes::JSON_COMPACT_SERIALIZATION, true, $detached_payload);
```

The fourth parameter is set to `true` to indicate that the payload is detached.
The output now contains all signatures but no payload. The payload is set in the last parameter `$detached_payload`.
Note that your payload is encoded in Base 64.

## How To Encrypt

### Initialize components

If you want to encrypt data, you must initialize:

* [A compression manager](component/compression_manager.md)
* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The encrypter itself](component/encrypter.md)

### Create a JWE

First, you must create an [encryption instruction](object/encryption_instruction.md) for each encryption you want to create:

```php
use Jose\EncryptionInstruction;

$instruction1 = new EncryptionInstruction();
$instruction1->setRecipientKey($first_recipient_public_key)
    ->setUnprotectedHeader([
        'alg' => 'RSA-OAEP-256',
    ]);

$instruction2 = new EncryptionInstruction();
$instruction2>setRecipientKey($second_recipient_public_key)
   ->setSenderKey($my_private_key)
   ->setUnprotectedHeader([
        'alg' => 'ECDH-ES',
        'foo' => 'bar',
   ]);
```

Then, you can encrypt your input:

```php
$input = 'The input to encrypt';
$instructions = [$instruction1, $instruction2];
$shared_protected_header = [
    'enc' => 'A256CBC-HS512',
    'zip' => 'DEF'
];
$shared_unprotected_header = [];

$output = $encrypter->encrypt($input, $instructions, JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $shared_protected_header, $shared_unprotected_header);
```

#### Important note

With this library, you can create encrypt an input using multiple instructions.
In this case, the Key Management Mode is determined according to the used algorithms.

You cannot create multiple encryptions if the Key Management Mode are not compatible.
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

### Output

The supported serialization modes can be found in [the Compact Serialization mode page](OutputModes.md).

The output depends on the output format you set and the number of instructions. It could be:

| Output Mode \ Number of instruction |   1    |        2+        |
|-------------------------------------|--------|------------------|
| Compact JSON Serialization          | string | array of strings |
| Flattened JSON Serialization        | string | array of strings |
| JSON Serialization                  | string | string           |


### Additional Authenticated Data

This library supports Additional Authenticated Data (AAD).

Note that this data is not available when using Compact JSON Serialization mode.

```php
$output = $encrypter->encrypt($input, $instructions, $shared_protected_header, $shared_unprotected_header, JSONSerializationModes::JSON_SERIALIZATION, 'foo,bar,baz');
```

## How To Load

### Initialize components

If you want to load data, you must initialize:

* [A compression manager](component/compression_manager.md)
* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [A checker manager](component/checker_manager.md)
* [The loader itself](component/loader.md)

### Load a JWS or JWE

```php
$output = $loader->load($input);
```

### Verify a JWS

### Decrypt a JWE
