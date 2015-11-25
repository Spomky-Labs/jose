The JWA Manager
===============

The JWA manager will load and manage all algorithms you want to you.

# Supported algorithms

This library supports the following algorithms:

* Signature:
    * none: `Jose\Algorithm\Signature\None`,
    * HS256: `Jose\Algorithm\Signature\HS256`,
    * HS384: `Jose\Algorithm\Signature\HS384`,
    * HS512: `Jose\Algorithm\Signature\HS512`,
    * RS256: `Jose\Algorithm\Signature\RS256`,
    * RS384: `Jose\Algorithm\Signature\RS384`,
    * RS512: `Jose\Algorithm\Signature\RS512`,
    * PS256: `Jose\Algorithm\Signature\PS256`,
    * PS384: `Jose\Algorithm\Signature\PS384`,
    * PS512: `Jose\Algorithm\Signature\PS512`,
    * ES256: `Jose\Algorithm\Signature\ES256`,
    * ES384: `Jose\Algorithm\Signature\ES384`,
    * ES512: `Jose\Algorithm\Signature\ES512`
* Encryption:
    * Key encryption:
        * dir: `Jose\Algorithm\KeyEncryption\Dir`,
        * A128KW: `Jose\Algorithm\KeyEncryption\A128KW`,
        * A192KW: `Jose\Algorithm\KeyEncryption\A192KW`,
        * A256KW: `Jose\Algorithm\KeyEncryption\A256KW`,
        * ECDH-ES: `Jose\Algorithm\KeyEncryption\ECDHES`,
        * ECDH-ES+A128KW: `Jose\Algorithm\KeyEncryption\ECDHESA128KW`,
        * ECDH-ES+A192KW: `Jose\Algorithm\KeyEncryption\ECDHESA192KW`,
        * ECDH-ES+A256KW: `Jose\Algorithm\KeyEncryption\ECDHESA256KW`,
        * PBES2-HS256+A128KW: `Jose\Algorithm\KeyEncryption\PBES2HS256A128KW`,
        * PBES2-HS384+A192KW: `Jose\Algorithm\KeyEncryption\PBES2HS384A192KW`,
        * PBES2-HS512+A256KW: `Jose\Algorithm\KeyEncryption\PBES2HS512A256KW`,
        * RSA1_5: `Jose\Algorithm\KeyEncryption\RSA15`,
        * RSA-OAEP: `Jose\Algorithm\KeyEncryption\RSAOAEP`,
        * RSA-OAEP-256: `Jose\Algorithm\KeyEncryption\RSAOAEP256`,
        * A128GCMKW: `Jose\Algorithm\KeyEncryption\A128GCMKW`,
        * A192GCMKW: `Jose\Algorithm\KeyEncryption\A192GCMKW`,
        * A256GCMKW: `Jose\Algorithm\KeyEncryption\A256GCMKW`
    * Content encryption:
        * A128CBC-HS256: `Jose\Algorithm\ContentEncryption\A128CBCHS256`,
        * A192CBC-HS384: `Jose\Algorithm\ContentEncryption\A192CBCHS384`,
        * A256CBC-HS512: `Jose\Algorithm\ContentEncryption\A256CBCHS512`,
        * A128GCM: `Jose\Algorithm\ContentEncryption\A128GCM`,
        * A192GCM: `Jose\Algorithm\ContentEncryption\A192GCM`,
        * A256GCM: `Jose\Algorithm\ContentEncryption\A256GCM`

*Note: all GCM algorithms need [PHP Crypto](https://github.com/bukka/php-crypto) Extension.*

# The manager

The JWA manager is really easy to use.
You just have to create an instance of `Jose\JWAManager` and add each algorithm you want to use.

```php
<?php

use Jose\JWAManager;
use Jose\Algorithm\Signature\HS256;
use Jose\Algorithm\KeyEncryption\A256CBCHS512;
use Jose\Algorithm\ContentEncryption\PBES2HS512A256KW;

$jwa_manager = new JWAManager();

$jwa_manager->addAlgorithm(new HS256())
    ->addAlgorithm(new A256CBCHS512())
    ->addAlgorithm(new PBES2HS512A256KW());
```
