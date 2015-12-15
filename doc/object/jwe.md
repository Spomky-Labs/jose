The JWE object
==============

The JWE object is usually the output after a JWE string has been loaded.

This object provides the same methods as [JWT](jwt.md) and is also immutable.

Internally, the library uses the following methods:

* `getCiphertext()`: Returns the cipher text as displayed in the serialization representation.
* `getEncryptedKey()`: Returns the encrypted key as displayed in the serialization representation.
* `getAAD()`: Returns the AAD as displayed in the serialization representation.
* `getIV()`: Returns the IV as displayed in the serialization representation.
* `getTag()`: Returns the tag as displayed in the serialization representation.

Note that the methods `getPayload()`, `getClaims()`, `getClaim($key)` and `hasClaim($key)` are only available when the payload has been decrypted.
