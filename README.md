PHP JOSE Library
================

[![Join the chat at https://gitter.im/Spomky-Labs/jose](https://badges.gitter.im/Spomky-Labs/jose.svg)](https://gitter.im/Spomky-Labs/jose?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=develop)
[![Coverage Status](https://coveralls.io/repos/Spomky-Labs/jose/badge.svg?branch=develop&service=github)](https://coveralls.io/github/Spomky-Labs/jose?branch=develop)
[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=develop)](https://travis-ci.org/Spomky-Labs/jose)

[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/jose.svg?style=flat)](http://hhvm.h4cc.de/package/Spomky-Labs/jose)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/jose/badge.svg)](https://travis-ci.org/Spomky-Labs/jose)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee/big.png)](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/stable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/JOSE/downloads.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![License](https://poser.pugx.org/Spomky-Labs/JOSE/license.png)](https://packagist.org/packages/Spomky-Labs/JOSE)

This library aims to provide an implementation of:

* JW**S** [JSON Web Signature (RFC 7515)](https://tools.ietf.org/html/rfc7515),
* JW**T** [JSON Web Token (RFC 7519)](https://tools.ietf.org/html/rfc7519),
* JW**E** [JSON Web Encryption (RFC 7516)](http://tools.ietf.org/html/rfc7516),
* JW**A** [JSON Web Algorithms (RFC 7518)](http://tools.ietf.org/html/rfc7518).
* JW**K** [JSON Web Key (RFC 7517)](http://tools.ietf.org/html/rfc7517).

Tests vectors from [RFC 7520](http://tools.ietf.org/html/rfc7520) are fully implemented and all test pass.

This library supports JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).

The [RFC7797](https://tools.ietf.org/html/rfc7797) (SON Web Signature (JWS) Unencoded Payload Option) is not yet supported.

# Provided Features

## Supported Input Types:

* [x] Plain text
* [x] Array
* [x] JWTInterface object
* [x] jwk+json content type (JWKInterface object)
* [x] jwkset+json content type (JWKSetInterface object)
* [x] Detached content

## Supported Serialization Modes

* [x] JSON Compact Serialization Overview (JWS/JWE creation and loading)
* [x] JSON Flattened Serialization Overview (JWS/JWE creation and loading)
* [x] JSON General Serialization Overview (JWS/JWE creation and loading)

## Supported Compression Methods

* [x] Deflate —DEF—
* [x] GZip —GZ— *(this compression method is not described in the specification)*
* [x] ZLib —ZLIB— *(this compression method is not described in the specification)*

## Supported Key Types (JWK)

* [x] None keys (`none`)
* [x] Symmetric keys (`oct`)
* [x] Asymmetric keys based on RSA keys (`RSA`)
* [x] Asymmetric keys based on Elliptic Curves (`EC`)
* [x] Asymmetric keys based on Octet Key Pair (`OKP`)
* 
JWK objects support JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).

## Key Sets (JWKSet)

JWKSet is fully supported.

## Supported Signature Algorithms

* [x] HS256, HS384, HS512
* [x] ES256, ES384, ES512 (third party library needed)
* [x] RS256, RS384, RS512
* [x] PS256, PS384, PS512
* [x] none (**Please note that this is not a secured algorithm. DO NOT USE IT PRODUCTION!**)
* [x] Ed25519 (third party extension needed)
* [ ] Ed25519ph
* [ ] Ed448
* [ ] Ed448ph

## Supported Key Encryption Algorithms

* [x] dir
* [x] RSA1_5
* [x] RSA-OAEP
* [x] RSA-OAEP-256
* [x] ECDH-ES (third party library needed)
* [x] ECDH-ES+A128KW (third party library needed)
* [x] ECDH-ES+A192KW (third party library needed)
* [x] ECDH-ES+A256KW (third party library needed)
* [x] A128KW
* [x] A192KW
* [x] A256KW
* [x] PBES2-HS256+A128KW
* [x] PBES2-HS384+A192KW
* [x] PBES2-HS512+A256KW
* [x] A128GCMKW (third party extension recommended)
* [x] A192GCMKW (third party extension recommended)
* [x] A256GCMKW (third party extension recommended)
* [ ] X25519
* [ ] X448

## Supported Content Encryption Algorithms

* [x] A128CBC-HS256
* [x] A192CBC-HS384
* [x] A256CBC-HS512
* [x] A128GCM (third party extension recommended)
* [x] A192GCM (third party extension recommended)
* [x] A256GCM (third party extension recommended)

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* OpenSSL extension
* ![PHP 5.5.9+](https://img.shields.io/badge/PHP-5.5.9%2B-ff69b4.svg).

Please consider the following optional requirements:
* For AES-GCM based algorithms (`AxxxGCM` and `AxxxGCMKW`): [PHP Crypto](https://github.com/bukka/php-crypto) Extension (at least `v0.2.1`) is highly recommended as encryption/decryption is faster than the pure PHP implementation.
* For ECC based algorithms: [PHP ECC](https://github.com/phpecc/phpecc) (`v0.3` only and `fgrosse/phpasn1` version `dev-compat/php5-5 as v1.3.1`).
* For Ed25519 algorithm: [php-ed25519-ext](https://github.com/encedo/php-ed25519-ext) required

Please read performance test results concerning the ECC based algorithms. As the time needed to perform operation is very long compared to the other algorithms, we do not recommend their use.

# Continuous Integration

It has been successfully tested using `PHP 5.5.9`, `PHP 5.6` and `PHP 7` and `HHVM` with all algorithms.

We also track bugs and code quality using [Scrutinizer-CI](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE) and [Sensio Insight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee).

Coding Standards are verified by [StyleCI](https://styleci.io/repos/22874677).

Code coverage is analyzed by [Coveralls.io](https://coveralls.io/github/Spomky-Labs/jose).

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require spomky-labs/jose
```

By default, tests and documentation files are not included. If you want to test this project or read the documentation, please add the option `--prefer-source`.

```sh
composer require spomky-labs/jose --prefer-source
```

# How to use

## The Easiest Way To Create JWS/JWE

The easiest way to create a JWS with single signature or JWE with single recipient is to use our factories.

### Signed JWT (JWS)

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We create our payload
$payload = [
    'exp' => time()+3600, // Expiration claim (expires in 3600 seconds)
    'iat' => time(),      // Issued At claim
    'nbf' => time(),      // Not Before claim
    'aud' => 'My client', // Audience claim
    'iss' => 'My Server', // Issuer claim
    'sub' => 'My User',   // Subject claim
    'root'=> true,        // Custom claim
];

// We create our header
$header = [
    'cty' => 'JWT',
    'alg' => 'RS512',
];

// We load our private key used to sign
$jwk = JWKFactory::createFromKeyFile(/path/to/my/private.rsa.encrypted.key', 'Secret');

// We create our JWS
$jws = JWSFactory::createJWSToCompactJSON($payload, $jwk, $header);
```

### Encrypted JWT (JWE)

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWEFactory;

// In this example, the payload will be the JWS created above

// We create our header
$header = [
    'alg' => 'RSA1_5',
    'enc' => 'A256GCM',
];

// We load the public key of the recipient
$jwk = JWKFactory::createFromKeyFile(/path/to/my/public.rsa.key');

// We create our JWE
$jwe = JWEFactory::createJWEToCompactJSON($jws, $jwk, $header);
```

Have a look at [How to use](doc/Use.md) to know how to load your JWT and discover all possibilities provided by this library.

# Performances

Take a look on the test results performed by [Travis-CI](https://travis-ci.org/Spomky-Labs/jose).
We added some tests to verify the performance of each algorithm.

*Please note that the time per signature will be different on your platform.*

The conclusions reached regarding these results are:

* Signature operations:
  * The HMAC signature performances are very good.
  * The RSA signature performances are good.
  * The ECC signature performances are very bad. This is due to the use of a pure PHP library.
* Key Encryption operations:
  * The algorithms based on RSA are very good.
  * The AES GCM Key Wrapping algorithms are very good if the extension is installed, else performances are bad.
  * The AES Key Wrapping algorithms are good.
  * The PBES2-* algorithms performances bad, except if you use small salt and low count which is not what you intent to do.
  * The ECC encryption performances are very bad. This is due to the use of a pure PHP library.
* Content Encryption operations:
  * All A128CBC-* algorithms are very good. 
  * A128GCM-* algorithms are very good if the extension is installed, else performances are bad.

To conclude, if you use shared keys, you will prefer HMAC signature algorithms and AES/AES GCM key wrapping algorithms.
If you use public/private key pairs, you will prefer RSA algorithms for signature and key encryption.

**At this moment, we do not recommend the use of ECC algorithms.**

## Signature/Verification Performances

Hereafter a table with all signature/verification test results.

|  Algorithm  |    Signature    |  Verification   |
|-------------|-----------------|-----------------|
| none        |   0.002120 msec |   0.002561 msec |
| HS256       |   0.063560 msec |   0.011048 msec |
| HS384       |   0.008521 msec |   0.013590 msec |
| HS512       |   0.009749 msec |   0.011101 msec |
| RS256       |   3.185160 msec |   0.408080 msec |
| RS384       |   2.673111 msec |   0.392590 msec |
| RS512       |   2.616920 msec |   0.387020 msec |
| PS256       |   2.711060 msec |   0.338850 msec |
| PS384       |   2.658789 msec |   0.305960 msec |
| PS512       |   2.691140 msec |   0.352941 msec |
| ES256       | 119.703550 msec | 335.086281 msec |
| ES384       | 201.914010 msec | 571.660171 msec |
| ES512       | 316.626689 msec | 895.848720 msec |
| Ed25519     |   0.042379 msec |   0.109930 msec |

## Key Encryption Performances

### Direct Key

Not tested as there is no ciphering process with this algorithm.

### Key Agreement

|    Algorithm    |  Key Agreement  |
|-----------------|-----------------|
| ECDH-ES (P-256) | 196.068900 msec |
| ECDH-ES (P-384) | N/A             |
| ECDH-ES (P-521) | 568.323238 msec |

### Key Agreement With Key Wrapping

|    Algorithm           |    Wrapping     |    Unwrapping   |
|------------------------|-----------------|-----------------|
| ECDH-ES+A128KW (P-256) | 201.839530 msec | 210.227959 msec |
| ECDH-ES+A128KW (P-384) | N/A             | N/A             |
| ECDH-ES+A128KW (P-521) | 577.361839 msec | 580.698538 msec |
| ECDH-ES+A192KW (P-256) | 221.429391 msec | 227.398269 msec |
| ECDH-ES+A192KW (P-384) | N/A             | N/A             |
| ECDH-ES+A192KW (P-521) | 591.375620 msec | 591.996751 msec |
| ECDH-ES+A256KW (P-256) | 204.114299 msec | 220.426919 msec |
| ECDH-ES+A256KW (P-384) | N/A             | N/A             |
| ECDH-ES+A256KW (P-521) | 596.029930 msec | 572.769132 msec |

### Key Wrapping

|    Algorithm       |    Wrapping     |    Unwrapping   |
|--------------------|-----------------|-----------------|
| A128KW                |   2.684588 msec |   2.543530 msec |
| A192KW                |   2.597601 msec |   2.532120 msec |
| A256KW                |   2.644479 msec |   2.608180 msec |
| A128GCMKW             |   0.022180 msec |   0.015359 msec |
| A128GCMKW(1)          |   9.724200 msec |   8.727851 msec |
| A192GCMKW             |   0.020292 msec |   0.014329 msec |
| A192GCMKW(1)          |   9.288480 msec |   9.948759 msec |
| A256GCMKW             |   0.020370 msec |   0.014551 msec |
| A256GCMKW(1)          |   9.685671 msec |   8.994040 msec |
| PBES2-HS256+A128KW(2) |  12.351940 msec |  12.727599 msec |
| PBES2-HS384+A192KW(2) |  15.622742 msec |  16.451840 msec |
| PBES2-HS512+A256KW(2) |  15.600979 msec |  15.592752 msec |

* *(1) Tests using the PHP/Openssl method instead of the PHP Crypto extension*
* *(2) Tests using default salt length (512 bits) and counts (4096) values*

### Key Encryption

|    Algorithm |   Encryption    |    Decryption   |
|--------------|-----------------|-----------------|
| RSA 1_5      |   1.056662 msec |   2.835732 msec |
| RSA-OAEP     |   0.314999 msec |   2.594349 msec |
| RSA-OAEP-256 |   0.320430 msec |   2.721188 msec |

### Content Encryption

|    Algorithm  |   Encryption    |    Decryption   |
|---------------|-----------------|-----------------|
| A128CBC-HS256 |   0.070095 msec |   0.034094 msec |
| A192CBC-HS384 |   0.031948 msec |   0.025988 msec |
| A256CBC-HS512 |   0.025034 msec |   0.012875 msec |
| A128GCM       |   0.070095 msec |   0.034094 msec |
| A128GCM(1)    |  67.502975 msec |  57.278872 msec |
| A192GCM       |   0.070095 msec |   0.034094 msec |
| A192GCM(1)    |  64.872026 msec |  64.872026 msec |
| A256GCM       |   0.070095 msec |   0.034094 msec |
| A256GCM(1)    |  61.682940 msec |  57.463884 msec |

* *(1) Tests using the PHP/Openssl method instead of the PHP Crypto extension*

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
