The Signature Instruction object
================================

To sign an input, you have to create a `SignatureInstruction` object.

This object will contain the private key and headers (protected or unprotected headers) you want to use.

Your instruction will be passed to the `Signer` object.

```php
use Jose\SignatureInstruction;

$instruction  = new SignatureInstruction(
    $my_private_key,
    [
        'alg' => 'HS512',
    ],
    [
        'unprotected' => 'bar',
    ]
);
```
