The Encrypter
=============

The Encrypter will perform encryption. You can encrypt an input using one or more keys.

To use our `Encrypter` object, you need to inject:
* a [JWA Manager](jwa_manager.md),
* a [Compression Manager](compression_manager.md),
* a [Payload Converter Manager](payload_converter_manager.md).

```php
use Jose\Encrypter;

$encrypter = new Encrypter($my_jwa_manager, $my_compression_manager, $my_payload_converter_manager);
```
