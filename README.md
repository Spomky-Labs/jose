PHP JOSE Library
================

[![Join the chat at https://gitter.im/Spomky-Labs/jose](https://badges.gitter.im/Spomky-Labs/jose.svg)](https://gitter.im/Spomky-Labs/jose?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/jose/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/Spomky-Labs/jose/?branch=develop)
[![Coverage Status](https://coveralls.io/repos/Spomky-Labs/jose/badge.svg?branch=master&service=github)](https://coveralls.io/github/Spomky-Labs/jose?branch=master)
[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose)

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

It also implements the following specifications:

* Tests vectors from [RFC 7520](http://tools.ietf.org/html/rfc7520) (fully implemented and all test pass).
* JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).
* Unencoded Payload Option [RFC7797](https://tools.ietf.org/html/rfc7797).

# Provided Features

## Supported Input Types:

JWS or JWE objects support every input that can be serialized:

* [x] String
* [x] Any variable of object that can be encoded/decoded into JSON:
    * [x] Primitives: integer, float...
    * [x] Array
    * [x] Objects that implement the `\JsonSerializable` interface such as:
        * [x] jwk+json content type (JWKInterface object)
        * [x] jwkset+json content type (JWKSetInterface object)

The [detached content](https://tools.ietf.org/html/rfc7515#appendix-F) is also supported.

Unencoded payload is supported. This means you can sign and verify payload without base64 encoding operation.
As per the [RFC7797](https://tools.ietf.org/html/rfc7797), the `b64` header MUST be protected.
When `b64` header is set, the `crit` protected header with value `b64` in its array of values is mandatory.

## Supported Serialization Modes

* [x] Compact JSON Serialization Syntax (JWS/JWE creation and loading)
* [x] Flattened JSON Serialization Syntax (JWS/JWE creation and loading)
* [x] General JSON Serialization Syntax (JWS/JWE creation and loading)

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
* [x] ES256, ES384, ES512
* [x] RS256, RS384, RS512
* [x] PS256, PS384, PS512
* [x] none (**Please note that this is not a secured algorithm. DO NOT USE IT PRODUCTION!**)
* [x] Ed25519 ([third party extension required](https://github.com/encedo/php-ed25519-ext))
* [ ] Ed448

*Please note that the [EdDSA signature algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for algorithms `Ed25518` and `Ed448` may change. Use with caution.*

## Supported Key Encryption Algorithms

* [x] dir
* [x] RSA1_5
* [x] RSA-OAEP
* [x] RSA-OAEP-256
* [x] ECDH-ES
* [x] ECDH-ES+A128KW
* [x] ECDH-ES+A192KW
* [x] ECDH-ES+A256KW
* [x] A128KW
* [x] A192KW
* [x] A256KW
* [x] PBES2-HS256+A128KW
* [x] PBES2-HS384+A192KW
* [x] PBES2-HS512+A256KW
* [x] A128GCMKW (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] A192GCMKW (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] A256GCMKW (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] X25519 ([third party extension required](https://github.com/encedo/php-curve25519-ext))
* [ ] X448

*Please note that the [EdDSA encryption algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for algorithms `X25518` and `X448` may change. Use with caution.*

## Supported Content Encryption Algorithms

* [x] A128CBC-HS256
* [x] A192CBC-HS384
* [x] A256CBC-HS512
* [x] A128GCM (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] A192GCM (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] A256GCM (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-ff69b4.svg),
* OpenSSL extension.

Please consider the following optional requirements:
* For AES-GCM based algorithms (`AxxxGCM` and `AxxxGCMKW`): [PHP Crypto](https://github.com/bukka/php-crypto) Extension (at least `v0.2.1`) is highly recommended as encryption/decryption is faster than the pure PHP implementation.
* For Ed25519 algorithm: [php-ed25519-ext](https://github.com/encedo/php-ed25519-ext) required
* For X25519 algorithm: [php-curve25519-ext](https://github.com/encedo/php-curve25519-ext) required

Please read performance test results below concerning the ECC based algorithms.
As the time needed to perform operation is long compared to the other algorithms, we do not recommend their use.

# Continuous Integration

It has been successfully tested using `PHP 5.6` and `PHP 7` and `HHVM` with all algorithms.

We also track bugs and code quality using [Scrutinizer-CI](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE) and [Sensio Insight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee).

Coding Standards are verified by [StyleCI](https://styleci.io/repos/22874677).

Code coverage is analyzed by [Coveralls.io](https://coveralls.io/github/Spomky-Labs/jose).

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require spomky-labs/jose
```

# How to use

Have a look at [How to use](doc/Use.md) to know how to load your JWT and discover all possibilities provided by this library.

# Performances

Please read the [performance page](doc/Performance.md) to know how fast are the algorithms supported by this library.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
