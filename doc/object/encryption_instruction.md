The Encryption Instruction object
=================================

To encrypt an input, you have to create a `EncryptionInstruction` object.

This object will contain the public key of the recipient and unprotected headers you want to use and will be passed to the `Encrypter` object. It also contains the private key of the sender if needed (e.g. use ECDSA-ES algorithm).

```php
use SpomkyLabs\Jose\EncryptionInstruction;

$instruction  = new EncryptionInstruction();
$instruction->setRecipientKey($recipient_public_key)
    ->setSenderKey($sender_private_key)
    ->setUnprotectedHeader([
        'foo' => 'bar',
    ]);
```
