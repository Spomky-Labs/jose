How to use
==========

# The objects

Each operation you will perform with this library uses objects.
Before to start, you need to know object types provided by this library and the methods you can call.

* [The keys (JWK)](object/jwk.md)
* [The key sets (JWKSet)](object/jwkset.md)
* The Jose:
    * [JWT](object/jwt.md)
    * [JWS](object/jws.md)
    * [JWE](object/jwe.md)
* The instructions:
    * [Signature instruction](object/signature_instruction.md)
    * [Encryption instruction](object/encryption_instruction.md)

# The operations

Depending on operations you want to perform, you have to initialize required components first.

## How To Sign

### Initialize components

If you want to sign data, you must initialize:

* [A JWT manager](component/jwt_manger.md)
* [A JWA manager](component/jwa_manger.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The signer itself](component/signer.md)

### Create a JWS

...

## How To Encrypt

### Initialize components

If you want to encrypt data, you must initialize:

* [A compression manager](component/compression_manger.md)
* [A JWT manager](component/jwt_manger.md)
* [A JWA manager](component/jwa_manger.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [The encrypter itself](component/encrypter.md)

### Create a JWE

...

## How To Load

### Initialize components

If you want to load data, you must initialize:

* [A compression manager](component/compression_manger.md)
* [A JWK manager](component/jwk_manger.md)
* [A JWKSet manager](component/jwkset_manger.md)
* [A JWT manager](component/jwt_manger.md)
* [A JWA manager](component/jwa_manger.md)
* [A payload converter manager](component/payload_converter_manager.md)
* [A checker manager](component/checker_manager.md)
* [The loader itself](component/loader.md)

### Load JWS or JWE

...
