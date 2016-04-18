How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [Signed JWT (JWS)](object/jws.md)
* [Encrypted JWT (JWE)](object/jwe.md)
* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)

# The operations

* [Sign a payload or claims](operation/Sign.md)
* [Verify JWS Signatures](operation/Verify.md)
* [Check claims](operation/Check.md)
* [Encrypt a message](operation/Encrypt.md)
* [Decrypt a JWE](operation/Decrypt.md)

# PSR-3 Messages

The `Signer`, `Verifier`, `Encrypter` and `Decrypter` classes are able to send debug messages compliant with the [PSR-3 Specification](http://www.php-fig.org/psr/psr-3/).
All you have to do is to call the method `enableLogging($logger)` (`$logger` is a valid `Psr\Log\LoggerInterface` object.

Factories also support logging messages (except the `JWKFactory`), but the logger is passed as an argument of all static methods:
In general, it is the last argument.

Example
-------

```php
$jwe = JWEFactory::createJWEToCompactJSON($payload, $recipient_key, $shared_protected_headers, $logger);
```
