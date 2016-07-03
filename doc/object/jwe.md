The JWE object
==============

When you want to encrypt a payload (claims, key, message...), you will need to create a JWE object and add recipients.

A JWE object can be easily created using the `JWEFactory` provided by this library:

```php
use Jose\Factory\JWEFactory;

$jwe = JWEFactory::createJWE(
    'My important message',
    [
        'enc' => 'A256CBC-HS512',
        'alg' => 'RSA-OAEP-256',
        'zip' => 'DEF',
    ]
    );
```

The first parameter is the payload (in this example, this is a message).
The second parameter is the shared protected header and contains all header parameters that are common for all recipients.
In the above example, This header indicates the key encryption algorithm ('RSA-OAEP-256'), the content encryption algorithm ('A256CBC-HS512') and that the payload is compressed before encryption using the method 'DEF' (deflate).

The variable `$jwe` now contains an object that implements `Jose\Object\JWEInterface`.

The methods available are:

* `getPayload()`: Return the payload of the JWS.
* `hasClaims()`: Return true if the payload is an array, else false.
* `getClaims()`: Return all claims.
* `hasClaim($key)`: Return true is the claim exists.
* `getClaim($key)`: Return the claim. If it does not exist, an exception is thrown.
* `countRecipients()`: Return the number of recipients
* `getRecipients()`: Return the all recipients
* `getRecipient($index)`: Return the recipient at the index `$index`
* `getSharedProtectedHeaders()`: Return the shared protected headers
* `getSharedProtectedHeader($key)`: Return the shared protected header at index `$index`
* `hasSharedProtectedHeader($key)`: Return true if the shared protected header at index `$index` exists, else false
* `getSharedHeaders()`: Return the shared headers
* `getSharedHeader($key)`: Return the shared header at index `$index`
* `hasSharedHeader($key)`: Return true if the shared header at index `$index` exists, else false
* `toCompactJSON($index)`: Return the compact JSON representation of the signature at index $index.
* `toFlattenedJSON($index)`: Return the flattened JSON representation of the signature at index $index.
* `toJSON()`: Return the general JSON representation of the JWS.
