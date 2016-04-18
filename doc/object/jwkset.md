The JWKSet object
=================

# Overview

The JWKSet object represents a key set and is able to store multiple keys.
This object implements the interface `Jose\Object\JWKSetInterface` and provides the following methods:
* `getKey($index)`: get the key at index `$index`
* `getKeys()`: get all keys
* `addKey(JWKInterface $key)`: add a key
* `removeKey($key)`: remove a key at index `$index`

Note that a JWKSet object
* is countable: you can call method `count()`,
* is traversable: you can use a JWK as `foreach` argument
* is serializable: You can call `json_encode($jwkset)` to display the key set as a string (e.g. `{'keys':[{'kty':'oct', 'k':'abcdef...'}]}`). Such string is mainly used to share public keys through an URL.
* can be used like an array
    * `$jwkset[] = $jwk;`: Add a new key in the key set
    * `$jwkset[$index];`: Return the key at the index `$index`
    * `unset($jwkset[$index]);`: Remove the key at the index `$index`

This library provides a class that implements this interface: `Jose\Object\JWKSet`.

Example:

```php
use Jose\Object\JWKSet;

$jwkset = new JWKSet();

$jwkset = $jwkset->addKey($key1); // Remember that the object is immutable. The method 'addKey' returns a new JWKSet object.
print_r(json_encode($jwkset)); // {'keys':[{'kty':'oct', 'k':'abcdef...'}]}
```

# Key Factory

Your key sets may be stored in a json encoded string or are available through an URL.
You can easily load and create key sets from several sources using the `Jose\Factory\JWKFactory` factory provided with this library.

## Create a Key from values

## Create a Key from a JWKSet Url (`jku`)

## Create a Key from a X509 Certificate Url (`x5u`)

# Key Selection

JWKSet object can contain several keys. To easily find a key according to constraint, a method `selectKey` is available.

```php
// Find a key used to encrypt/decrypt
$jwk_set->selectKey('enc');

// Find a key used to sign/verify
$jwk_set->selectKey('sig');

// Find a key used to sign/verify using the algorithm 'RS256'
$jwk_set->selectKey('sig', 'RS256');

// Find a key used to encrypt/decrypt with kid = '0123456789'
$jwk_set->selectKey('enc', null, ['kid'=>'0123456789']);

// Find a key used to sign/verify with sha256 thumbprint = '0123456789'
$jwk_set->selectKey('sig', null, ['x5t#256'=>'0123456789']);
```

Again, we recommend you to use key/value pairs:

* `kid`: the ID of the key
* `use`: the usage of the key (`sig` for signature or `enc` for encryption operations)
* `alg`: the algorithm allowed for this key

The selection of the best key to use will be more efficient.
