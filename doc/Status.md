Status of the implementation
============================

# JWT #

## Supported ##

* Input supported:
    * [x] Plain text
    * [x] Array
    * [x] JWTInterface object
    * [x] jwk+json content type (JWKInterface object)
    * [x] jwkset+json content type (JWKSetInterface object)
    * [x] Detached content

* Serialization modes supported:
    * [x] JSON Compact Serialization Overview (JWS/JWE creation and loading)
    * [x] JSON Flattened Serialization Overview (JWS/JWE creation and loading)
    * [x] JSON Serialization Overview (JWS/JWE creation and loading)

* Compression support for JWE objects:
    * [x] Deflate —DEF—
    * [x] GZip —GZ— *(this compression method is not described in the specification)*
    * [x] ZLib —ZLIB— *(this compression method is not described in the specification)*

# JWA #

## Supported algorithms ##

* Signature:
    * [x] HS256, HS384, HS512
    * [x] ES256, ES384, ES512
    * [x] RS256, RS384, RS512
    * [x] PS256, PS384, PS512
    * [x] none (**Please note that this is not a secured algorithm. DO NOT USE IT PRODUCTION!**)
* Encryption:
    * Key Encryption:
        * [x] dir
        * [x] RSA1_5
        * [x] RSA-OAEP
        * [x] RSA-OAEP-256
        * [x] ECDH-ES
        * [x] ECDH-ES+A128KW
        * [x] ECDH-ES+A192KW
        * [x] ECDH-ES+A256KW
        * [x] A128KW
        * [x] A192KW
        * [x] A256KW
        * [x] PBES2-HS256+A128KW
        * [x] PBES2-HS384+A192KW
        * [x] PBES2-HS512+A256KW
        * [x] A128GCMKW
        * [x] A192GCMKW
        * [x] A256GCMKW
    * Content Encryption:
        * [x] A128CBC-HS256
        * [x] A192CBC-HS384
        * [x] A256CBC-HS512
        * [x] A128GCM
        * [x] A192GCM
        * [x] A256GCM

## Unsupported algorithms ##

**None!** All algorithms described in the specification are supported. Some of these algorithms requires additional dependencies to be used.

# JWK and JWKSet #

JWK and JWKSet are fully supported

# JWKManager and JWKSetManager #

This project provides key and key set managers. These managers are able to find individual keys or key sets according to the header of data loaded.

You can extend them to add your own methods to find specific keys using header values.
For example, if you manage your keys using X509 thumbprint, you can add a method to read the value of "x5t" or "x5t#256" parameters and find the correct key.
