Algorithms and Performance
==========================

We added some tests to verify the performance of each algorithm.
These tests are not executed during unit and functional testing as they may take a very long time.

*Please note that the time per operation will be different on your platform.*

The conclusions reached regarding these results are:

* Signature operations:
  * The HMAC signature performances are very good.
  * The RSA signature performances are good.
  * The ECC signature performances very good **only if OpenSSL supports EC signatures**.
* Key Encryption operations:
  * The algorithms based on RSA are very good.
  * The AES GCM Key Wrapping algorithms are very good if the extension is installed, else performances are bad.
  * The AES Key Wrapping algorithms are good.
  * The PBES2-* algorithms performances are bad, except if you use small salt and low count which is not what you intent to do.
  * The ECC encryption performances are poor. This is due to the use of a pure PHP library.
* Content Encryption operations:
  * All A128CBC-* algorithms are very good. 
  * A128GCM-* algorithms are very good if the extension is installed, else performances are bad.

To conclude, if you use shared keys, you will prefer HMAC signature algorithms and AES/AES GCM key wrapping algorithms.
If you use public/private key pairs, you will prefer RSA algorithms for signature and key encryption.

**At this moment, we do not recommend the use of ECC algorithms for encryption/decryption with our library.**

# Signature/Verification Operations

Hereafter a table with all signature/verification test results.

|    Algorithm    |    Signature    |  Verification   |
|-----------------|-----------------|-----------------|
| none            |   0.002120 msec |   0.002561 msec |
| HS256           |   0.063560 msec |   0.011048 msec |
| HS384           |   0.008521 msec |   0.013590 msec |
| HS512           |   0.009749 msec |   0.011101 msec |
| RS256           |   3.185160 msec |   0.408080 msec |
| RS384           |   2.673111 msec |   0.392590 msec |
| RS512           |   2.616920 msec |   0.387020 msec |
| PS256           |   2.711060 msec |   0.338850 msec |
| PS384           |   2.658789 msec |   0.305960 msec |
| PS512           |   2.691140 msec |   0.352941 msec |
| ES256           |   1.375458 msec |   0.685260 msec |
| ES256(1)        |  46.056359 msec |  85.660450 msec |
| ES384           |   1.336381 msec |   1.702900 msec |
| ES384(1)        |  70.218148 msec | 143.770418 msec |
| ES512           |   1.124258 msec |   1.578491 msec |
| ES512(1)        | 110.474162 msec | 202.372239 msec |
| EdDSA (Ed25519) |   0.042379 msec |   0.109930 msec |
| EdDSA (Ed448)   |        N/A msec |        N/A msec |

* *(1) Tests using the PHPECC library in case the EC signature is not supported by OpenSSL*

# Key Encryption Operations

## Direct Key

Not tested as there is no ciphering process with this algorithm.

## Key Agreement

|    Algorithm     |  Key Agreement  |
|------------------|-----------------|
| ECDH-ES (P-256)  | 126.203909 msec |
| ECDH-ES (P-384)  | 204.835088 msec |
| ECDH-ES (P-521)  | 304.262869 msec |
| ECDH-ES (X25519) |   1.099138 msec |
| ECDH-ES (X448)   |        N/A msec |

## Key Agreement With Key Wrapping

|    Algorithm           |    Wrapping     |    Unwrapping   |
|------------------------|-----------------|-----------------|
| ECDH-ES+A128KW (P-256) | 129.029691 msec |  39.483140 msec |
| ECDH-ES+A128KW (P-384) | 196.413360 msec |  62.773380 msec |
| ECDH-ES+A128KW (P-521) | 302.115850 msec | 104.237161 msec |
| ECDH-ES+A192KW (P-256) | 117.906761 msec |  45.322330 msec |
| ECDH-ES+A192KW (P-384) | 198.598192 msec |  82.638860 msec |
| ECDH-ES+A192KW (P-521) | 309.309719 msec | 113.017519 msec |
| ECDH-ES+A256KW (P-256) | 134.307990 msec |  46.188619 msec |
| ECDH-ES+A256KW (P-384) | 198.677561 msec |  72.755859 msec |
| ECDH-ES+A256KW (P-521) | 315.579700 msec | 103.662469 msec |

## Key Wrapping

|    Algorithm       |    Wrapping     |    Unwrapping   |
|--------------------|-----------------|-----------------|
| A128KW                |   2.684588 msec |   2.543530 msec |
| A192KW                |   2.597601 msec |   2.532120 msec |
| A256KW                |   2.644479 msec |   2.608180 msec |
| A128GCMKW             |   0.022180 msec |   0.015359 msec |
| A128GCMKW(1)          |   9.724200 msec |   8.727851 msec |
| A192GCMKW             |   0.020292 msec |   0.014329 msec |
| A192GCMKW(1)          |   9.288480 msec |   9.948759 msec |
| A256GCMKW             |   0.020370 msec |   0.014551 msec |
| A256GCMKW(1)          |   9.685671 msec |   8.994040 msec |
| PBES2-HS256+A128KW(2) |  12.351940 msec |  12.727599 msec |
| PBES2-HS384+A192KW(2) |  15.622742 msec |  16.451840 msec |
| PBES2-HS512+A256KW(2) |  15.600979 msec |  15.592752 msec |

* *(1) Tests using the PHP/Openssl method instead of the PHP Crypto extension*
* *(2) Tests using default salt length (512 bits) and counts (4096) values*

## Key Encryption

|    Algorithm |   Encryption    |    Decryption   |
|--------------|-----------------|-----------------|
| RSA 1_5      |   1.056662 msec |   2.835732 msec |
| RSA-OAEP     |   0.314999 msec |   2.594349 msec |
| RSA-OAEP-256 |   0.320430 msec |   2.721188 msec |

## Content Encryption

|    Algorithm  |   Encryption    |    Decryption   |
|---------------|-----------------|-----------------|
| A128CBC-HS256 |   0.070095 msec |   0.034094 msec |
| A192CBC-HS384 |   0.031948 msec |   0.025988 msec |
| A256CBC-HS512 |   0.025034 msec |   0.012875 msec |
| A128GCM       |   0.070095 msec |   0.034094 msec |
| A128GCM(1)    |  67.502975 msec |  57.278872 msec |
| A192GCM       |   0.070095 msec |   0.034094 msec |
| A192GCM(1)    |  64.872026 msec |  64.872026 msec |
| A256GCM       |   0.070095 msec |   0.034094 msec |
| A256GCM(1)    |  61.682940 msec |  57.463884 msec |

* *(1) Tests using the PHP/Openssl method instead of the PHP Crypto extension*
