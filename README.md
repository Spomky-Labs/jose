# PHP JOSE Library

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)
[![Coverage Status](https://coveralls.io/repos/Spomky-Labs/jose/badge.svg?branch=master&service=github)](https://coveralls.io/github/Spomky-Labs/jose?branch=master)

[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose)
[![StyleCI](https://styleci.io/repos/22874677/shield)](https://styleci.io/repos/22874677)

[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/jose.png)](http://hhvm.h4cc.de/package/Spomky-Labs/jose)
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

# Important note

> Note 1: this library is still in development. The first stable release will be tagged as v1.0.x. All tags v0.x.y must be considered as unstable.

> Note 2: if you use Symfony, [a bundle](https://github.com/Spomky-Labs/JoseBundle) is in development.

This library provides all objects and components to perform signature, verification, encryption and decryption according to the RFCs listed above.

Some of classes provided are abstract and you must implement the missing methods.
In addition, you will have to instantiate, initialize and inject all objects and components to the signer, encrypter and loader services.

You will be afraid of all of this and you will think that this library is very complicated to use. AND YOU ARE RIGHT!

That is why we created to other projects to ease the use of this library:

* [Jose Service](https://github.com/Spomky-Labs/jose-service): this project uses Pimple to provide only one service to rule them all.
* [Jose Bundle](https://github.com/Spomky-Labs/JoseBundle): a Symfony 2.7+ bundle that provides easy to use services

Finally, this library and all these projects are still in active development. Do not hesitate to send us your feedback!

# Status of implementations

[Please see this page](doc/Status.md).

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 5.5.9+](https://img.shields.io/badge/PHP-5.5.9%2B-ff69b4.svg).

Please consider the following optional requirements:
* AES-GCM based algorithms (`AxxxGCM` and `AxxxGCMKW`): [PHP Crypto](https://github.com/bukka/php-crypto) Extension (at least `v0.2.1`).

# Continuous Integration

It has been successfully tested using `PHP 5.5.9`, `PHP 5.6` and `PHP 7` and `HHVM`.

Please note that `AxxxGCM` and `AxxxGCMKW` tests are not performed as [PHP Crypto](https://github.com/bukka/php-crypto) is not available on `HHVM` platform.
Anyway, as the this library should work fine.

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

Your classes are ready to use? Have a look at [How to use](doc/Use.md) to create or load your first JWT objects.

# Unsecured JWS

This library supports unsecured `JWS` (`none` algorithm).

**Unsecured `JWS` is something you probably do not want to use.**
After you loaded data you received, you should verify that the algorithm used is not `none`.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
