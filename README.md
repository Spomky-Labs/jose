# PHP JOSE Library

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE/?branch=master)
[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose)
[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/JOSE.png)](http://hhvm.h4cc.de/package/Spomky-Labs/JOSE)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee/big.png)](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/stable.png)](https://packagist.org/packages/Spomky-Labs/JOSE) [![Total Downloads](https://poser.pugx.org/Spomky-Labs/JOSE/downloads.png)](https://packagist.org/packages/Spomky-Labs/JOSE) [![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/JOSE) [![License](https://poser.pugx.org/Spomky-Labs/JOSE/license.png)](https://packagist.org/packages/Spomky-Labs/JOSE)

This library aims to provide an implementation of:

* JW**S** [JSON Web Signature (draft 41)](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41),
* JW**T** [JSON Web Token (draft 32)](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32),
* JW**E** [JSON Web Encryption (draft 40)](http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40),
* JW**A** [JSON Web Algorithms (draft 40)](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40).
* JW**K** [JSON Web Key (draft 40)](http://tools.ietf.org/html/draft-ietf-jose-json-web-key-40).

**This library is not yet complete! Do not use it in production.**

## Status of implementations: ##

[Please see this page](doc/Status.md).

## The Release Process ##

We manage the releases of the library through features and time-based models.

- A new patch version comes out every month when you made backwards-compatible bug fixes.
- A new minor version comes every six months when we added functionality in a backwards-compatible manner.
- A new major version comes every year when we make incompatible API changes.

The meaning of "patch" "minor" and "major" comes from the Semantic [Versioning strategy](http://semver.org/).

This release process applies for all versions.

### Backwards Compatibility

We allow developers to upgrade with confidence from one minor version to the next one.

Whenever keeping backward compatibility is not possible, the feature, the enhancement or the bug fix will be scheduled for the next major version.

## Prerequisites ##

This library needs at least

* `PHP 5.4`
* PHP Extension: `BC Math` or `GMP` (`GMP` is highly recommended!)
* `OpenSSL` library for PHP
* `phpseclib/phpseclib` library for RSA and AES algorithms.
* `mdanter/ecc` library for Elliptic Curves algorithms.
* [PHP Crypto](https://github.com/bukka/php-crypto) Extension for AES GCM algorithms.

It has been successfully tested using `PHP 5.4` to `PHP 5.6`.
Tests with `HHVM` fail because of `phpseclib/phpseclib` which is not compatible.

## Installation ##

The preferred way to install this library is to rely on Composer:

    {
        "require": {
            // ...
            "spomky-labs/jose": "~0.0.0"
        }
    }

## Extend the library ##

This library only contains the logic. You must extend classes (algorithms, compression, managers...) to define setters and getters.

Look at [Extend classes](doc/Extend.md) for more informations and examples.

## How to use ##

Your classes are ready to use? Have a look at [How to use](doc/Use.md) to create or load your first JWT objects.

## Todo

[Next modifications](doc/Todo.md).

## Contributing

Requests for new features, bug fixed and all other ideas to make this library usefull are welcome. [Please follow these best practices](doc/Contributing.md).

## Licence

This software is release under [MIT licence](LICENSE).
