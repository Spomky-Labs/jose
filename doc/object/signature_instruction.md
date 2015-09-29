The Signature Instruction object
================================

To sign an input, you have to create a `SignatureInstruction` object.

This object will contain the private key and headers (protected or unprotected headers) you want to use and will be passed to the `Signer` object.

```php
$instruction  = new SignatureInstruction();
$instruction->setKey($my_private_key)
    ->setProtectedHeader([
        'alg' => 'HS512',
    ])
    ->setUnprotectedHeader([
        'foo' => 'bar',
    ]);
```
