The JWT object
==============

The JWT object is the base of output objects after loading (see [JWS](jws.md) and [JWE](jwe.md).

Important note: A JWT object is immutable. It means that if you modify a claim or a header value, you will obtain a new object.

This object provides the following methods:

* `setProtectedHeader(array $headers)`: Sets the protected header.
* `getProtectedHeaderValue($key)`: Returns the protected header value with key $key`, else null.
* `setProtectedHeaderValue($key, $value)`: Sets the protected header value with key `$key`.
* `setUnprotectedHeader(array $headers)`:  Sets the unprotected header.
* `getUnprotectedHeaderValue($key)`: Returns the unprotected header value with key $key`, else null.
* `setUnprotectedHeaderValue($key, $value)`:  Sets the unprotected header value with key `$key`.
* `getHeaderValue($key)`: Returns the header value (protected or unprotected) with key $key`, else null.
* `getHeaderOrPayloadValue($key)`: Returns the header (protected or unprotected) or payload value with key $key`, else null.
* `setPayload($payload)`: Sets the value of the payload
* `getPayload()`: Returns the value of the payload.
* `getPayloadValue($key)`: Returns the payload value with key $key`, else null. Only available if the payload is an associative array.
* `getType()`: Convenient method for `getHeaderValue('jty')`.
* `getContentType()`: Convenient method for `getHeaderValue('cty')`.
* `getIssuer()`: Convenient method for `getHeaderOrPayloadValue('iss')`.
* `getSubject()`: Convenient method for `getHeaderOrPayloadValue('sub')`.
* `getAudience()`: Convenient method for `getHeaderOrPayloadValue('aud')`.
* `getExpirationTime()`: Convenient method for `getHeaderOrPayloadValue('exp')`.
* `getNotBefore()`: Convenient method for `getHeaderOrPayloadValue('nbf')`.
* `getIssuedAt()`: Convenient method for `getHeaderOrPayloadValue('iat')`.
* `getJWTID()`: Convenient method for `getHeaderOrPayloadValue('jti')`.
* `getAlgorithm()`: Convenient method for `getHeaderValue('alg')`.
* `getKeyID()`: Convenient method for `getHeaderValue('kid')`.
* `getJWKUrl()`: Convenient method for `getHeaderValue('jku')`.
* `getJWK()`: Convenient method for `getHeaderValue('jwk')`.
* `getX509Url()`: Convenient method for `getHeaderValue('x5u')`.
* `getX509CertificateChain()`: Convenient method for `getHeaderValue('x5c')`.
* `getX509CertificateSha1Thumbprint()`: Convenient method for `getHeaderValue('x5t')`.
* `getX509CertificateSha256Thumbprint()`: Convenient method for `getHeaderValue('x5t#256')`.
* `getCritical()`: Convenient method for `getProtectedHeaderValue('crit')`.

Internally, the library uses the following methods:

* `getEncodedProtectedHeader()`: Returns the protected header as displayed in the JWT representation
* `getEncodedPayload()`: Returns the payload as displayed in the JWT representation
*  `getInput()`: Returns the input as passed to the `Loader` object
