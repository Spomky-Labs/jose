The JWT object
==============

The JWT object is the base of output objects after loading (see [JWS](jws.md) and [JWE](jwe.md).

Important note: A JWT object is immutable and you cannot modify it.

This object provides the following methods:

* `getHeaders()`: Returns the protected header value with key $key`, else null.
* `hasHeader($key)`: Returns the protected header value with key $key`, else null.
* `getHeader($key)`: Returns the protected header value with key $key`, else null.
* `getProtectedHeaders()`: Returns the protected header value with key $key`, else null.
* `hasProtectedHeader($key)`: Returns the protected header value with key $key`, else null.
* `getProtectedHeader($key)`: Returns the protected header value with key $key`, else null.
* `getUnprotectedHeaders()`: Returns the unprotected header value with key $key`, else null.
* `hasUnprotectedHeader($key)`: Returns the unprotected header value with key $key`, else null.
* `getUnprotectedHeader($key)`: Returns the unprotected header value with key $key`, else null.
* `hasHeaderOrClaim($key)`: Returns the header (protected or unprotected) or payload value with key $key`, else null.
* `getHeaderOrClaim($key)`: Returns the header (protected or unprotected) or payload value with key $key`, else null.
* `getClaims()`: Returns the value of the payload.
* `hasClaim($key)`: Returns the value of the payload.
* `getClaim($key)`: Returns the value of the payload.
* `getPayload()`: Returns the value of the payload.


Internally, the library uses the following methods:

* `getInput()`: Returns the input as passed to the `Loader` object
