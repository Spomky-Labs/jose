The JWS object
==============

The JWS object is usually the output after a JWS string has been loaded.

This object provides the same methods as [JWT](jwt.md).

Internally, the library uses the following methods. You should not use these methods directly.

* `getSignature()`: Returns the signature as displayed in the serialization representation.
* `setSignature($signature)`: Sets the signature as displayed in the serialization representation.
