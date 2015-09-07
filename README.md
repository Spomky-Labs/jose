# PHP JOSE Library

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)

[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose)
[![StyleCI](https://styleci.io/repos/22874677/shield)](https://styleci.io/repos/22874677)

[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/jose.png)](http://hhvm.h4cc.de/package/Spomky-Labs/jose)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/jose/badge.svg)](https://travis-ci.org/Spomky-Labs/jose)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee/big.png)](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/stable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/JOSE/downloads.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![License](https://poser.pugx.org/Spomky-Labs/JOSE/license.png)](https://packagist.org/packages/Spomky-Labs/JOSE)

[![Documentation Status](https://readthedocs.org/projects/spomky-labsjose/badge/?version=latest)](https://readthedocs.org/projects/spomky-labsjose/?badge=latest)

This library aims to provide an implementation of:

* JW**S** [JSON Web Signature (RFC 7515)](https://tools.ietf.org/html/rfc7515),
* JW**T** [JSON Web Token (RFC 7519)](https://tools.ietf.org/html/rfc7519),
* JW**E** [JSON Web Encryption (RFC 7516)](http://tools.ietf.org/html/rfc7516),
* JW**A** [JSON Web Algorithms (RFC 7518)](http://tools.ietf.org/html/rfc7518).
* JW**K** [JSON Web Key (RFC 7517)](http://tools.ietf.org/html/rfc7517).

Tests vectors from [RFC 7520](http://tools.ietf.org/html/rfc7520) are partially implemented.

# Status of implementations

[Please see this page](doc/Status.md).

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 5.4+](https://img.shields.io/badge/PHP-5.4%2B-ff69b4.svg).

Depending on algorithms you want to use, please consider the following optional requirements:
* Elliptic Curves based algorithms (`ESxxx` signatures, `ECDHES` encryptions):
    * [`mdanter/ecc`](https://github.com/mdanter/phpecc) (v0.3) library.
* RSA based algorithms (`RSxxx` or `PSxxx` signatures, `RSA1_5`, `RSA_OAEP`, `RSA_OAEP-256`...):
    * `phpseclib/phpseclib` (v2.0.x).
* AES based algorithms (excluding `AES-GCM`):
    * `OpenSSL` library for AES algorithms.
    * or `MCrypt` library for AES algorithms.
    * or `phpseclib/phpseclib` (v2.0.x).
* AES-GCM based algorithms:
    * [PHP Crypto](https://github.com/bukka/php-crypto) Extension for AES GCM algorithms (not available on `PHP 7` and `HHVM`).

It has been successfully tested using `PHP 5.4` to `PHP 5.6` with all algorithms.

Tests with `PHP 7` and `HHVM` are incomplete because of [PHP Crypto](https://github.com/bukka/php-crypto).

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require spomky-labs/jose "1.0.0@dev"
```

# Extend the library

This library only contains the logic. You must extend classes (algorithms, compression, managers...) to define setters and getters.

Look at [Extend classes](doc/Extend.md) for more information and examples.

# How to use

Your classes are ready to use? Have a look at [How to use](doc/Use.md) to create or load your first JWT objects.

# Unsecured JWS

This library supports unsecured `JWS` (`none` algorithm).

**Unsecured `JWS` is something you probably do not want to use.**
After you loaded data you received, you should verify that the algorithm used is not `none`.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
