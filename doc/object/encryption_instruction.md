The Encryption Instruction object
=================================

To encrypt an input, you have to create a `EncryptionInstruction` object.

This object contains the public key of the recipient and unprotected headers you want to use.
If the algorithm you will use to encrypt requires the sender private key (e.g. ECDSA-ES algorithm), you can set this key in this object.

Your encryption instructions will be passed to the `Encrypter` object.

```php
use Jose\EncryptionInstruction;

$instruction  = new EncryptionInstruction(
    $recipient_public_key,
    $sender_private_key,
    [
        'alg' => 'ECDH-ES',
        'enc' => 'A256CBC-HS512',
    ],
    [
        'unprotected' => 'foo',
    ]
);
```
