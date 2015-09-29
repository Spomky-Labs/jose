The Signer
==========

The Signer will perform all signatures. You can sign an input using one or more keys.

To use our `Signer` object, you need to inject:
* a [JWT Manager](jwt_manager.md),
* a [JWA Manager](jwa_manager.md),
* a [Payload Converter Manager](payload_converter_manager.md).

```php
use SpomkyLabs\Jose\Signer;

$signer = new Signer();
$signer->setJWTManager($my_jwt_manager)
    ->setJWAManager($my_jwa_manager)
    ->setPayloadConverter($my_payload_converter_manager)
```

Then, you must create a [signature instruction](../object/signature_instruction.md) for each signature you want to create:

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

Now, you are ready to sign your input:

```php
$input = 'The input to sign';
$instructions = [$instruction1, $instruction2];

$output = $signer->sign($input, $instructions);
```

The output is an array that contains two signatures.

By default, the output is in [Compact Serialization mode](../OutputModes.md). You can choose another mode if needed:

```php
$output = $signer->sign($input, $instructions, JSONSerializationModes::JSON_SERIALIZATION);
```
