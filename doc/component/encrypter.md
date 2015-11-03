The Encrypter
=============

The Encrypter will perform encryption. You can encrypt an input using one or more keys.

To use our `Encrypter` object, you need to inject:
* a [JWT Manager](jwt_manager.md),
* a [JWA Manager](jwa_manager.md),
* a [Compression Manager](compression_manager.md),
* a [Payload Converter Manager](payload_converter_manager.md).

```php
use SpomkyLabs\Jose\Encrypter;

$encrypter = new Encrypter();
$encrypter->setJWTManager($my_jwt_manager)
    ->setJWAManager($my_jwa_manager)
    ->setCompressionManager($my_compression_manager)
    ->setPayloadConverter($my_payload_converter_manager);
```
