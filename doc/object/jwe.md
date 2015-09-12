The JWE object
==============

The JWE object is usually the output after a JWE string has been loaded.

This object provides the same methods as [JWT](jwt.md) and the following methods:

* `getEncryptionAlgorithm()`: Convenient method for `getHeaderValue('enc')`.
* `getZip()`: Convenient method for `getHeaderValue('zip')`.

Internally, the library uses the following methods. You should not use these methods directly.

* `getCiphertext()`: Returns the cipher text as displayed in the serialization representation.
* `setCiphertext($ciphertext)`: Sets the cipher text as displayed in the serialization representation.
* `getEncryptedKey()`: Returns the encrypted key as displayed in the serialization representation.
* `setEncryptedKey($encrypted_key)`: Sets the encrypted key as displayed in the serialization representation.
* `getAAD()`: Returns the AAD as displayed in the serialization representation.
* `setAAD($aad)`: Sets the AAD as displayed in the serialization representation.
* `getIV()`: Returns the IV as displayed in the serialization representation.
* `setIV($iv)`: Sets the IV as displayed in the serialization representation.
* `getTag()`: Returns the tag as displayed in the serialization representation.
* `setTag($tag)`: Sets the tag as displayed in the serialization representation.

Note that the payload (method `getPayload()`) is only available when it has been decrypted.
