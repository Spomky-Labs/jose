Key types and algorithms
========================

This page lists algorithms and supported key types.

# Signature

* `ES256`, `ES384` and `ES512`: `EC` (Elliptic Curves) type,
* `RS256`, `RS384`,  `RS512`, `PS256`, `PS384` and  `PS512`: `RSA` type,
* `HS256`, `HS384` and `HS512`: `oct` type,
* `none`: `none` type,
* `Ed25519`, `Ed448`: `OKP` type.

# Key encryption

* `dir`: `oct` type,
* `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and `ECDH-ES+A256KW`: `EC` (Elliptic Curves) type,
* `RSA1_5`, `RSA-OAEP` and `RSA-OAEP-256`: `RSA` type,
* `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` and `PBES2-HS512+A256KW`: `oct` type,
* `A256KW`, `A384KW` and `A512KW`: `oct` type,
* `A256GCMKW`, `A384GCMKW` and `A512GCMKW`: `oct` type.
* `X25519`, `X448`: `OKP` type.
