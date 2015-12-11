The Signer
==========

The Signer will perform all signatures. You can sign an input using one or more keys.

To use our `Signer` object, you need to inject:
* a [JWA Manager](jwa_manager.md),
* a [Payload Converter Manager](payload_converter_manager.md).

```php
use Jose\Signer;

$signer = new Signer($my_jwa_manager, $my_payload_converter_manager);
```
