The JWK object
==============

# Overview

The JWK object represents a key. Depending on the key properties, it can be used to sign, verify a signature, encrypt or decrypt.
The class `Jose\Object\JWK` implements the interface `Jose\Object\JWKInterface` and provides the following methods:
* `get($name)`: get the value at key `$name`. Throws an exception if the key does not exist.
* `has($name)`: return true if the key has a key/value pair `$name`
* `getAll()`: get all key/value pairs
* `thumbprint($algorithm)`: returns the thumbprint of the key using the hash algorithm `$algorithm`. You can use any algorithm return by the `hash_algos()` method. 
* `toPublic()`: if the key is private (RSA or EC private key), this method returns the public key.

Note that a JWK object
* is serializable: You can call `json_encode($jwk)` to display the key set as a string (e.g. `{'kty':'oct', 'k':'abcdef...'}`).
* is immutable: you cannot modify it

# Create a `JWK` object

To create a `JWK` object, simply instantiate the class and set values.
Please note that the key/value pair `kty` MUST be set. 

```php
use `Jose\Object\JWK`;

$jwk = new JWK([
    'kty' => 'oct',
    'kid' => 'My First Key',
    'k'   => 'abcdef',
]);
```

# Key values

Values depend on the key type. [Read this page](../Keys.md) to know which key types are supported.

## None key (`none`)

The value `kty` is mandatory.
```php
$jwk = new JWK([
    'kty' => 'none',
]);
```

## Asymmetric key (`oct`)


```php
use Base64Url\Base64Url;

$jwk = new JWK([
    'kty' => 'oct',
    'k'   => Base64Url::encode($my_binary_string),
]);
```

The value of `k` is your binary key encoded in base 64 url safe. This value is mandatory.

## Symmetric key

### RSA key

`RSA` public and private keys are very similar. The difference is that a public key only contains `n` (modulus) and `e` (exponent) values.
The values `kty`, `n` and `e` are mandatory.
The key is considered as private when it contains a `d` value.

```php
// A public key
$jwk = new JWK([
    'kty' => 'RSA',
    'n'   => 'abcdef',
    'e'   => 'AQAB',
]);
```

```php
// A private key
$jwk = new JWK([
    'kty' => 'RSA',
    'n'   => 'abcdef',
    'e'   => 'AQAB',
    'd'   => 'ghijkl',
    'dp'   => '123456',
    'dq'   => '987654',
    'qi'   => 'ABCDEF',
]);

$public_key = $jwk->toPublic();
```

The values of `n`, `e`, `d`, `dp`, `dq` and `qi` are encoded in base 64 url safe.

### ECC key

As `RSA` keys, `EC` public and private keys are very similar. The difference is that a public key only contains `x` and `y` (coordinates) values.
The values `kty`, x` and `y` are mandatory.
A private key contains a `d` value.

```php
// A public key
$jwk = new JWK([
    'kty' => 'EC',
    'crv' => 'P-256',
    'x'   => 'abcdefghij',
    'y'   => '0123456789',
]);
```

```php
// A private key
$jwk = new JWK([
    'kty' => 'EC',
    'crv' => 'P-256',
    'x'   => 'abcdefghij',
    'y'   => '0123456789',
    'd'   => 'ABCDEFGHIJ',
]);

$public_key = $jwk->toPublic();
```

The values of `x`, `y` and `d` are encoded in base 64 url safe.

## Octet key pair (`OKP`)

This kind of key is used by the:
- signature algorithms Ed25519 and Ed448
- encryption algorithms X25519 nd X448

At the moment, only algorithm Ed25519 is supported.

A private key contains a `d` value.

```php
// A private OKP key
$public = new JWK([
   'kty' => 'OKP',
   'crv' => 'Ed25519',
   'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
]);

// A private OKP key
$private = new JWK([
   'kty' => 'OKP',
   'crv' => 'Ed25519',
   'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
   'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
]);
```

The values of `x` and `d` are encoded in base 64 url safe.

## Other Key/Value Pairs

Depending on your needs, you may use other key/value pairs.

We recommend you to use:

* `kid`: the ID of the key
* `use`: the usage of the key (`sig` for signature or `enc` for encryption operations)
* `alg`: the algorithm allowed for this key

More details on [the JWK specification](http://tools.ietf.org/html/rfc7517#section-4).

You can use custom key/value pairs:

```php
$jwk = new JWK([
    'kid' => 'MY_KEY_#1',
    'alg' => 'HS256',
    'kty' => 'oct',
    'k'   => 'GawgguFyGrWKav7AX4VKUg',
    'foo' => 'bar',
]);
```

# JWK Methods

```php
use `Jose\Object\JWK`;

$jwk = new JWK([
    'kty' => 'oct',
    'k'   => 'abcdef',
]);

$this->has('kty'); // Return true
$this->has('foo'); // Return false
$this->get('kty'); // Return 'oct'
$this->thumbprint('sha256'); // Return 'iBLRjibnjP0qSVQ2TnyD_CYLXSNz5hjwjLMdUkY-JQg'
$this->get('foo'); // Throws an exception as this key/value pair does not exist
```

# Key Factory

Your keys may be stored in a file (X509 certificate, PEM key or DER key) or are available through an URL.
You can easily load and create keys from several sources using the `Jose\Factory\JWKFactory` factory provided with this library.

## Create a Key from Values

You may need this method to create keys when you already have values (symmetric keys):

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'GawgguFyGrWKav7AX4VKUg',
]);
```

## Create a Key from a X509 Certificate File

Use this method to load a certificate an convert it into a JWK object.
The second argument allow you to add key/value pairs.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromCertificateFile('/path/to/the/certificate', ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added* 

The factory is able to load X509 Certificates store in PEM or DER format. This is done automatically.
This library also supports files that contain a certificate chain. In this case, all the chain is verified.

## Create a Key from a X509 Certificate

You can create a key file with an already loaded certificate file.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromCertificate($file_content, ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added*

## Create a Key from a X509 Certificate Resource

You can create a key file with an already loaded certificate file using the certificate resource.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromX509Resource($resource, ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added*

## Create a Key from a key file

This factory can load a key stored in a file.
Both PEM and DER formats are supported. If the key is encrypted, the secret must be passed (2nd argument).
Additional parameters can be set (3rd argument).

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromKeyFile('/path/to/the/key', 'secret', ['use' => 'sig', 'alg'=> 'RS256']);
```

## Create a Key from a key file content

You can create a key file with an already loaded key file.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromKey($file_content, 'secret', ['use' => 'sig', 'alg'=> 'RS256']);
```


## Create a Key from a X5C header parameter

If you load a JWT and it contains a header with key `X5C`, you can load this certificate to get the associated public key.
It is recommended to use this parameter only if it is protected.

In the following example, the variable `$jws` is a valid `JWS` object with one signature. Its protected header contain a `X5C` parameter.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromX5C($jws->getSignature(0)->getProtectedHeader('x5c'));
```
