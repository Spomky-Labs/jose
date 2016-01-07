The JWK object
==============

The JWK object represents a key. Depending on the key properties, it can be used to sign, verify a signature, encrypt or decrypt.

A JWK object is serializable. You can call `json_encode($jwk)` to display the key as a string (e.g. `{'kty':'oct', 'k':'abcdef...'}`).

**This object is immutable. It means that you cannot change any of its values.**

# Create a `JWK` object

To create a `JWK` object, simply instantiate the class and set values:

```php
use Jose\JWK;

$jwk = new JWK([
    'kid' => 'My First Key',
    'kty' => 'oct',
    'k'   => 'abcdef',
]);
```

*Please note that the parameter `kty` is mandatory*

# Key values

Values depend on the key type. [Read this page](../Keys.md) to know supported key type.

## None key (`none`)

```php
$jwk = new JWK([
    'kty' => 'none',
]);
```

## Assymetric key (`oct`)

```php
$jwk = new JWK([
    'kty' => 'oct',
    'k'   => 'abcdef',
]);
```

The value of `k` is your binary key encoded in base 64 url safe. This value is mandatory.

```php
use Base64Url\Base64Url;

$jwk = new JWK([
    'kty' => 'oct',
    'k'   => Base64Url::encode($my_binary_string),
]);
```

## Direct key (`dir`)

```php
$jwk = new JWK([
    'kty' => 'dir',
    'dir'   => 'abcdef',
]);
```

The value of `dir` is your binary key encoded in base 64 url safe. This value is mandatory.

## Symmetric key

### RSA key

`RSA` public and private keys are very similar. The difference is that a public key only contains `n` (modulus) and `e` (exponent) values.
The values `n` and `e` are mandatory.
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
```

### ECC key

As `RSA` keys, `EC` public and private keys are very similar. The difference is that a public key only contains `x` and `y` (coordinates) values.
The values `x` and `y` are mandatory.
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
```

## Other key key/value pairs

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

# Available methods

A `JWK` object implements the interface `Jose\JWKInterface` and provides the following methods:

* `getAll()`: all values
* `has($key)`: returns true if the JWK object has a value identified by the key `$key`, else false.
* `get($key)`: the value with key `$key`. Throws an exception if the key `$key` does not exist.
* `thumbprint($hash_algorithm)`: the key thumbprint with hash algorithm `$hash_algorithm`. Throws an exception if the hash algorithm is not supported.

```php
use Jose\JWK;

$jwk = new JWK([
    'kty' => 'oct',
    'k'   => 'abcdef',
]);

$this->has('kty'); // Return true
$this->has('foo'); // Return false
$this->get('kty'); // Return 'oct'
$this->thumbprint('sha256'); // Return 'iBLRjibnjP0qSVQ2TnyD_CYLXSNz5hjwjLMdUkY-JQg'
```

# Key Factory

Your keys may be stored in a file (X509 certificate, PEM key or DER key) or are available through an URL.
You can easily load and create keys from several sources using the `Jose\Factory\KeyFactory` factory provided with this library.

## Create a Key from Values

You may need this method to create keys when you already have values (symmetric keys):

```php
use Jose\Factory\KeyFactory;

$jwk = KeyFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'GawgguFyGrWKav7AX4VKUg',
]);
```

## Create a Key from a X509 Certificate File

Use this method to load a certificate an convert it into a JWK object.
The second argument allow you to add key/value pairs.

```php
use Jose\Factory\KeyFactory;

$jwk = KeyFactory::createFromCertificateFile('/path/to/the/certificate', ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that at this moment, only X509 Certificate in PEM format are supported*

## Create a Key from a X509 Certificate

You can create a key file with an already loaded certificate file.

```php
use Jose\Factory\KeyFactory;

$jwk = KeyFactory::createFromCertificateFile('-----BEGIN CERTIFICATE-----
MIICpzCCAhACAg4AMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEw.....', ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that at this moment, only X509 Certificate in PEM format are supported*

