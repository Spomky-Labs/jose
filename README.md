PHP JOSE Library
================

[![Join the chat at https://gitter.im/Spomky-Labs/jose](https://badges.gitter.im/Spomky-Labs/jose.svg)](https://gitter.im/Spomky-Labs/jose?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)
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

Tests vectors from [RFC 7520](http://tools.ietf.org/html/rfc7520) are partially implemented.

This library supports JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).

# Important note

> Note 1: this library is still in development. All tags v0.x.y must be considered as unstable.

> Note 2: if you use Symfony, [a bundle](https://github.com/Spomky-Labs/JoseBundle) is in development.

# Status of implementations

[Please see this page](doc/Status.md).

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 5.5.9+](https://img.shields.io/badge/PHP-5.5.9%2B-ff69b4.svg).

Please consider the following optional requirements:
* For AES-GCM based algorithms (`AxxxGCM` and `AxxxGCMKW`): [PHP Crypto](https://github.com/bukka/php-crypto) Extension (at least `v0.2.1`) is highly recommended as encryption/decryption is faster than the pure PHP implementation.
* For ECC based algorithms: [PHP ECC](https://github.com/phpecc/phpecc) (`v0.3` only).

# Continuous Integration

It has been successfully tested using `PHP 5.5.9`, `PHP 5.6` and `PHP 7` and `HHVM`.

Please note that tests using algorithms `AxxxGCM` and `AxxxGCMKW` are not performed as [PHP Crypto](https://github.com/bukka/php-crypto) is not available on `HHVM` platform.

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

Have a look at [How to use](doc/Use.md) to create or load your first JWT objects.

# Unsecured JWS 

This library supports unsecured `JWS` (`none` algorithm).

**Unsecured `JWS` is something you probably do not want to use.**
After you loaded data you received, you should verify that the algorithm used is not `none`.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
