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

* [A JWT manager](component/jwt_manager.md)
* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The signer itself](component/signer.md)

### Create a JWS

First, you must create a [signature instruction](object/signature_instruction.md) for each signature you want to create:

```php
use SpomkyLabs\Jose\SignatureInstruction;

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
$input = 'The input to sign';
$instructions = [$instruction1, $instruction2];

$output = $signer->sign($input, $instructions);
```

### Output

The output depends on the output format you set and the number of instructions. It could be:

| Output Mode \ Number of instruction |   1    |   2+  |
|-------------------------------------|--------|-------|
| Compact JSON Serialization          | string | array |
| Flattened JSON Serialization        | string | array |
| JSON Serialization                  | string | string|

By default, the output is in [Compact Serialization mode](OutputModes.md). You can choose another mode if needed:

```php
$output = $signer->sign($input, $instructions, JSONSerializationModes::JSON_SERIALIZATION);
```

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
* [A JWT manager](component/jwt_manager.md)
* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The encrypter itself](component/encrypter.md)

### Create a JWE

First, you must create an [encryption instruction](object/encryption_instruction.md) for each encryption you want to create:

```php
use SpomkyLabs\Jose\EncryptionInstruction;

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

$output = $encrypter->encrypt($input, $instructions, $shared_protected_header, $shared_unprotected_header);
```

### Output

The output depends on the output format you set and the number of instructions. It could be:

| Output Mode \ Number of instruction |   1    |   2+  |
|-------------------------------------|--------|-------|
| Compact JSON Serialization          | string | array |
| Flattened JSON Serialization        | string | array |
| JSON Serialization                  | string | string|

By default, the output is in [Compact Serialization mode](OutputModes.md). You can choose another mode if needed:

```php
$output = $encrypter->encrypt($input, $instructions, $shared_protected_header, $shared_unprotected_header, JSONSerializationModes::JSON_SERIALIZATION);
```

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
* [A JWK manager](component/jwk_maanger.md)
* [A JWKSet manager](component/jwkset_manager.md)
* [A JWT manager](component/jwt_manager.md)
* [A JWA manager](component/jwa_manager.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [A checker manager](component/checker_manager.md)
* [The loader itself](component/loader.md)

### Load JWS or JWE

...
