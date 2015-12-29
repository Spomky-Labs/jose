The Compression Manager
=======================

When you encrypt data or load a JWE, the payload may have been compressed.
This library supports compression.

# Supported compression methods

This library supports the following algorithms:

* Signature:
    * DEF: `Jose\Compression\Deflate`,
    * GZ: `Jose\Compression\GZip`,
    * ZLIB: `Jose\Compression\ZLib`

*Note: only `DEF` is described in the [RFC 7516](http://tools.ietf.org/html/rfc7516).*
*Others method should only used if both issuer and audience know how to use them*

# Custom compression method

If you need to use a custom compression method, you just have to create a class that implements `Jose\Compression\CompressionInterface`
and inject it onto the encrypter or decrypter objects.