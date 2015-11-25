The Encryption Instruction object
=================================

To encrypt an input, you have to create a `EncryptionInstruction` object.

This object contains the public key of the recipient and unprotected headers you want to use.
If the algorithm you will use to encrypt requires the sender private key (e.g. ECDSA-ES algorithm), you can set this key in this object.

Your encryption instruction will be passed to the `Encrypter` object.

```php
use Jose\EncryptionInstruction;

$instruction  = new EncryptionInstruction();
$instruction->setRecipientKey($recipient_public_key)
    ->setSenderKey($sender_private_key)
    ->setUnprotectedHeader([
        'foo' => 'bar',
    ]);
```
