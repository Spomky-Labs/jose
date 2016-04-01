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

## Create a Key from a X509 Certificate File

## Create a Key from a X509 Certificate
