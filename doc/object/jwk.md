The JWK object
==============

The JWK object represents a key. This object implements the interface `Jose\JWKInterface` and provides the following methods:
* `getValues()`: all values
* `setValues(array $values)`: set values of the key 
* `getValue($key)`:  the value with key `$key`. Returns null if the value does not exist.
* `setValue($key, $value)`: set the value `$value` at key `$key`
* `getKeyType()`: returns the key type. This method is a convenient method for `getValue('kty')`
* `getPublicKeyUse()`: returns the key type. This method is a convenient method for `getValue('use')`
* `getKeyOperations()`: returns the key type. This method is a convenient method for `getValue('key_ops')`
* `getAlgorithm()`: returns the key type. This method is a convenient method for `getValue('alg')`
* `getKeyID()`: returns the key type. This method is a convenient method for `getValue('kid')`
* `getX509Url()`: returns the key type. This method is a convenient method for `getValue('x5u')`
* `getX509CertificateChain()`: returns the key type. This method is a convenient method for `getValue('x5c')`
* `getX509CertificateSha1Thumbprint()`: returns the key type. This method is a convenient method for `getValue('x5t')`
* `getX509CertificateSha256Thumbprint()`: returns the key type. This method is a convenient method for `getValue('x5t#256')`

A JWK object is also serializable. You can call `json_encode($jwk)` to display the key as a string (e.g. `{'kty':'oct', 'k':'abcdef...'}`).
