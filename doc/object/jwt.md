The JWT object
==============

The JWT object is the base of output objects after loading (see [JWS](jws.md) and [JWE](jwe.md).

Important note: A JWT object is immutable and you cannot modify it.

This object provides the following methods:

* `getHeaders()`: Returns the headers of the JWT object (protected and unprotected).
* `hasHeader($key)`: Returns true if the header (protected or unprotected) identified by `$key` exists, else false.
* `getHeader($key)`: Returns the header (protected or unprotected) identified by the key `$key`. If the header does not exists, an exception is thrown.
* `getProtectedHeaders()`: Returns the protected headers of the JWT object.
* `hasProtectedHeader($key)`: Returns true if the protected header identified by `$key` exists, else false.
* `getProtectedHeader($key)`: Returns the protected header identified by the key `$key`. If the header does not exists, an exception is thrown.
* `getUnprotectedHeaders()`: Returns the unprotected headers of the JWT object.
* `hasUnprotectedHeader($key)`: Returns true if the unprotected header identified by `$key` exists, else false.
* `getUnprotectedHeader($key)`: Returns the unprotected header identified by the key `$key`. If the header does not exists, an exception is thrown.
* `hasHeaderOrClaim($key)`: Returns true if the JWT object contains a header or a claim identified by the key `$key`, else false.
* `getHeaderOrClaim($key)`: Returns the header or the claim identified by the key `$key`. If it does not exists, an exception is thrown.
* `hasClaims()`: Returns true if the payload may contain claims (i.e. the payload is an array).
* `getClaims()`: Returns all claims. This method throws an exception if the payload is not an array.
* `hasClaim($key)`: Returns true if the claim identified by the key `$key` exists, else false.
* `getClaim($key)`: Returns the claim identified by the key `$key`. If it does not exists, an exception is thrown.
* `getPayload()`: Returns the payload.


Internally, the library uses the following methods:

* `getInput()`: Returns the input as passed to the `Loader` object
