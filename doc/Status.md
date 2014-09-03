# Status of the implementation

## Loading and Creation of JWT

### Supported

* JSON Compact Serialization Overview
    * JWS (creation and loading):
        * Plain text
        * Array
    * JWE (creation and loading):
        * Plain text
        * Array
        * jwk+json and jwkset+json content type
* JSON Serialization Overview
    * JWS (creation and loading):
        * Plain text
        * Array
        * Raw data
    * JWE (loading only):
        * Plain text
        * Array
        * jwk+json and jwkset+json content type

* Compression support for JWE objects:
    * Deflate (DEF)
    * GZip (GZ)
    * ZLib (ZLIB)

### Unsupported

* JWS and JWE header:
    * `crit` parameter
* JSON Serialization Overview
    * JWE (creation only)
        * Plain text
        * Array
        * jwk+json and jwkset+json content type

## JWA

All required algorithms are supported (marked with a *).
Some Optionnal (o), Recommended (r) and Recommended+ (+) algorithms are also supported

### Supported algorithms:

* Signature:
    * HS256(*), HS384(o), HS512(o)
    * ES256(+), ES384(o), ES512(o)
    * RS256(r), RS384(o), RS512(o)
    * PS256(o), PS384(o), PS512(o)
    * none(o)
* Encryption:
    * Key Encryption:
        * dir(r)
        * RSA1_5(*)
        * RSA-OAEP(o)
        * RSA-OAEP-256(o)
        * ECDH-ES(+)
    * Content Encryption:
        * A128CBC-HS256(*)
        * A192CBC-HS384(o)
        * A256CBC-HS512(*)

### Unsupported algorithms:

* Encryption:
    * Key Encryption:
        * A128KW(r)
        * A192KW(o)
        * A256KW(r)
        * ECDH-ES+A128KW(r)
        * ECDH-ES+A192KW(0)
        * ECDH-ES+A256KW(r)
        * A128GCMKW(o)
        * A192GCMKW(o)
        * A256GCMKW(o)
        * PBES2-HS256+A128KW(o)
        * PBES2-HS384+A192KW(o)
        * PBES2-HS512+A256KW(o)
    * Content Encryption:
        * A128GCM(r)
        * A192GCM(o)
        * A256GCM(r)

## JWK:

JWK are partially supported (implementation is not finished, some interfaces are missing).

## JWKSet:

JWKSet are fully supported

## JWKManager:

### Unsupported

* Key load from x5* parameters
