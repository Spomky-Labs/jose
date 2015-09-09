The Compression Manager
=======================

When you encrypt data or load a JWE, the payload may have been compressed.
This library supports compression.

# Supported compression methods

This library supports the following algorithms:

* Signature:
    * DEF: `SpomkyLabs\Jose\Compression\Deflate`,
    * GZ: `SpomkyLabs\Jose\Compression\GZip`,
    * ZLIB: `SpomkyLabs\Jose\Compression\ZLib`

*Note: only DEF is described in the [RFC 7516](http://tools.ietf.org/html/rfc7516).*

# The manager

You just have to create an instance of `SpomkyLabs\Jose\Compression\CompressionManager` and add each algorithm you want to use.

```php
<?php

use SpomkyLabs\Jose\Compression\CompressionManager;
use SpomkyLabs\Jose\Compression\Deflate;

$compression_manager = new CompressionManager();

$compression_manager->addCompressionAlgorithm(new Deflate());
```

By default, all compression methods provided set the compression level to -1 (auto).
You can set a custom value between 0 (no compression) and 9 (maximum).

```php
<?php

use SpomkyLabs\Jose\Compression\CompressionManager;
use SpomkyLabs\Jose\Compression\Deflate;

$compression_manager = new CompressionManager();

$deflate = new Deflate();
$deflate->setCompressionLevel(6);

$compression_manager->addCompressionAlgorithm($deflate);
```
