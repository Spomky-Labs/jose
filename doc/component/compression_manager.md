The Compression Manager
=======================

When you encrypt data or load a JWE, the payload may have been compressed.
This library supports compression.

# Supported compression methods

This library supports the following algorithms:

* Signature:
    * DEF: `Jose\Compression\Deflate`,
    * GZ: `Jose\Compression\GZip`,
    * ZLIB: `Jose\Compression\ZLib`

*Note: only DEF is described in the [RFC 7516](http://tools.ietf.org/html/rfc7516).*

# The manager

You just have to create an instance of `Jose\Compression\CompressionManager` and add each algorithm you want to use.

```php
<?php

use Jose\Compression\CompressionManager;
use Jose\Compression\Deflate;

$compression_manager = new CompressionManager();

$compression_manager->addCompressionAlgorithm(new Deflate());
```

By default, all compression methods provided set the compression level to -1 (auto).
You can set a custom value between 0 (no compression) and 9 (maximum).

```php
<?php

use Jose\Compression\CompressionManager;
use Jose\Compression\Deflate;

$compression_manager = new CompressionManager();

$deflate = new Deflate();
$deflate->setCompressionLevel(6);

$compression_manager->addCompressionAlgorithm($deflate);
```
