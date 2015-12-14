The JWS object
==============

The JWS object is usually the output after a JWS string has been loaded.

This object provides the same methods as [JWT](jwt.md) and is also immutable.

Internally, the library uses the following methods. You should not use these methods directly.

* `getEncodedProtectedHeader()`: Returns the protected header as displayed in the JWT representation
* `getEncodedPayload()`: Returns the payload as displayed in the JWT representation
* `getSignature()`: Returns the signature as displayed in the serialization representation.
