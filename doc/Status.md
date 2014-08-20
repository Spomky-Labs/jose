# Status of the implementation

## JWT

JWT are partially supported

### Supported

* Compact Serialization Overview
    * JWS
    * JWE:
        * Plain text data
        * jwk+json and jwkset+json content type

### Unsupported

* JSON Serialization Overview
    * JWS
    * JWE
* Unprotected headers

## JWA
### Supported algorithms:

* Signature:
    * HS256, HS384, HS512
    * ES256, ES384, ES512
    * RS256, RS384, RS512
    * PS256, PS384, PS512
    * none
* Encryption:
    * Key Encryption:
        * dir
        * RSA
        * RSA-OAEP
        * RSA-OAEP-256
    * Content Encryption:
        * A128CBC-HS256
        * A192CBC-HS384
        * A256CBC-HS512

### Unsupported algorithms:

* Encryption:
    * Key Encryption:
        * A128KW
        * A192KW
        * A256KW
        * ECDH-ES
        * ECDH-ES+A128KW
        * ECDH-ES+A192KW
        * ECDH-ES+A256KW
        * A128GCMKW
        * A192GCMKW
        * A256GCMKW
        * PBES2-HS256+A128KW
        * PBES2-HS384+A192KW
        * PBES2-HS512+A256KW
    * Content Encryption:
        * A128GCM
        * A192GCM
        * A256GCM

## JWK:

JWKSet are partially supported

### Unsupported:

* Key load from x5* parameters

## JWKSet:

JWKSet are fully supported