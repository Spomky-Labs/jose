The Signer
==========

The Signer will perform all signatures. You can sign an input using one or more keys.

```php
use Jose\Factory\SignerFactory;
use Jose\Object\SignatureInstruction;

$signer = SignerFactory::createSigner(
    ['ES256', 'RS256'], // A list of algorithms we want to use
                        // This list must contain algorithm names or are objects that implement Jose\Algorithm\JWAInterface
    []                  // A list of payload converters (we do not need them here
);

// First signature instruction
$instruction1 = new SignatureInstruction(
    $key1,
    ['alg' => 'ES256']
);

// Second signature instruction
$instruction2 = new SignatureInstruction(
    $key2,
    ['alg' => 'RS256']
);

// List of instructions
$instructions = [
    $instruction1,
    $instruction2,
];

$jws = $signer->sign(
    'The message I want to sign',
    $instructions,
    JSONSerializationModes::JSON_SERIALIZATION
);
```
