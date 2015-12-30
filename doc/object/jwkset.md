The JWKSet object
=================

The JWKSet object represents a key set and is able to store multiple keys.
This object implements the interface `Jose\JWKSetInterface` and provides the following methods:
* `getKeys()`: get all keys
* `addKey(JWKInterface $key)`: add a key
* `removeKey($key)`: remove a key

Note that a JWKSet object
* is countable: you can call method `count()`,
* is traversable: you can use a JWK as `foreach` argument
* is serializable. You can call `json_encode($jwkset)` to display the key set as a string (e.g. `{'keys':{'kty':'oct', 'k':'abcdef...'}}`). Such string is mainly used to share public keys through an URL.
