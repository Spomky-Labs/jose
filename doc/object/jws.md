The JWS object
==============

When you want to sign a payload (claims, key, message...), you will need to create a JWS object and add signatures.

A JWS object can be easily create using the `JWSFactory` provided by this library:

```php
use Jose\Factory\JWSFactory;

$jws = JWSFactory::createJWS([
    'iss' => 'My server',
    'aud' => 'Your client',
    'sub' => 'Your resource owner',
    'exp' => time()+3600,
    'iat' => time(),
    'nbf' => time(),
]);
```

The variable `$jws` now contains an object that implements `Jose\Object\JWSInterface`.

The methods available are:

* `getPayload()`: Return the payload of the JWS.
* `hasClaims()`: Return true if the payload is an array, else false.
* `getClaims()`: Return all claims.
* `hasClaim($key)`: Return true is the claim exists.
* `getClaim($key)`: Return the claim. If it does not exist, an exception is thrown.
* `countSignatures()`: Return the number of signatures.
* `getSignatures()`: Return all signatures
* `getSignature($index)`: Return the signature at index $index. If the signature does not exist, an exception is thrown.
* `toCompactJSON($index)`: Return the compact JSON representation of the signature at index $index.
* `toFlattenedJSON($index)`: Return the flattened JSON representation of the signature at index $index.
* `toJSON()`: Return the general JSON representation of the JWS.
