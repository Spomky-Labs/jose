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
