# Status of the implementation #

## JWT ##

### Supported ###

Input supported:
* Plain text
* Array
* JWTInterface object
* jwk+json content type (JWKInterface object)
* jwkset+json content type (JWKSetInterface object)

Serialization modes supported:
* JSON Compact Serialization Overview (JWS/JWS creation and loading)
* JSON Flattened Serialization Overview (JWS/JWS creation and loading)
* JSON Serialization Overview (JWE creation in this mode is not supported)

Compression support for JWE objects:
* Deflate —DEF—
* GZip —GZ— *(this compression method is not described in the specification)*
* ZLib —ZLIB— *(this compression method is not described in the specification)*

### Unsupported ###

* JSON Serialization Overview
    * JWE (creation only)

## JWA ##

### Supported algorithms ###

* Signature:
    * HS256, HS384, HS512
    * ES256, ES384, ES512
    * RS256, RS384, RS512
    * PS256, PS384, PS512
    * none
* Encryption:
    * Key Encryption:
        * dir
        * RSA1_5
        * RSA-OAEP
        * RSA-OAEP-256
        * ECDH-ES
        * ECDH-ES+A128KW
        * ECDH-ES+A192KW
        * ECDH-ES+A256KW
        * A128KW
        * A192KW
        * A256KW
        * PBES2-HS256+A128KW
        * PBES2-HS384+A192KW
        * PBES2-HS512+A256KW
        * A128GCMKW
        * A192GCMKW
        * A256GCMKW
    * Content Encryption:
        * A128CBC-HS256
        * A192CBC-HS384
        * A256CBC-HS512
        * A128GCM
        * A192GCM
        * A256GCM

### Unsupported algorithms ###

**None!** All algortihms described in the specification are supported.

## JWK ##

JWK are fully supported

## JWKSet ##

JWKSet are fully supported

## JWKManager ##

This project provides a key manager. This manager is able to find keys according to the header of data loaded.

You can extend it to add your own methods to find specific keys using header values. For example, if you manage your keys using X509 thumprint, you can add a method to read the value of "x5t" or "x5t#256" parameters and find the correct key.
