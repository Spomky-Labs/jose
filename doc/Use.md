How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [Signed JWT (JWS)](object/jws.md)
* [Encrypted JWT (JWE)](object/jwe.md)
* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)

# The operations

* [Sign a payload or claims](operation/Sign.md)
* [Verify JWS Signatures](operation/Verify.md)
* [Check claims](operation/Check.md)
* [Encrypt a message](operation/Encrypt.md)
* [Decrypt a JWE](operation/Decrypt.md)

# JWT Creator and JWTLoader

In general, you will need to create and load JWS or encrypted JWS (JWS as payload of a JWE) in compact JSON serialization mode.
To ease the creation and loading of such data, the library provides two classes that have convenient methods.

Read the [dedicated page](operation/JWTCreator_And_JWTLoader.md) to know how to instantiate and use these classes.
