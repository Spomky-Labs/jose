Verify JWS Signatures
=====================

This library provides a `Loader` object able to load and verify signatures of a JWS.
If the JWS contains claims, **these claims are not verified by this loader. This step is done by the [Checker](Check.md)**.

# The Most Common Way

To verify a JWS, you will need:

* the JWS string (Compact, Flattened or in General JSON Representation Mode),
* a symmetric key, a public key ([JWK object](../object/jwk.md)) or a key set ([JWKSet object](../object/jwkset.md)),
* the `Loader` object,
* a list of algorithms allowed to be used.

```php
use Jose\Factory\JWKFactory;
use Jose\Loader;

// We load the key set from an URL
$jwk_set = JWKFactory::createFromJKU('https://www.googleapis.com/oauth2/v3/certs');

// We create our loader.
$loader = new Loader();

// This is the input we want to load verify.
$input = 'eyJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE0NTE0NjkwMTcsImlhdCI6MTQ1MTQ2OTAxNywiZXhwIjoxNDUxNDcyNjE3LCJpc3MiOiJNZSIsImF1ZCI6IllvdSIsInN1YiI6Ik15IGZyaWVuZCJ9.mplHfnyXzUdlEkPmykForVM0FstqgiihfDRTd2Zd09j6CZzANBJbZNbisLerjO3lR9waRlYvhnZu_ewIAahDwmVTfpSeKKABbAyoTHXTH2WLgMPLtOAsoausUf584eAAj_kyldIOV8a83Qz1NztZHVD3DbGTiCN0BOj-qnc65yQmEDEYK5cxG1xC22YK5aohZ3xm8ixwNZpxYr8cNOkauASYjPGODbHqY_gjQ-aKA21kxbYgwM6mDYSc3QRej1_3m6bD3jKPsK4jv3yzosVMEXOparf4sEb8q_zCPMDJAJgZZ8VICwJdgYnJkQuIutS-w3_iT-riKl8fkgmJezQVkg';

// The signature is verified using our key set.
$jws = $loader->loadAndVerifySignatureUsingKeySet(
    $input,
    $jwk_set,
    ['RS256'],
    $signature_index
);
```

An exception is thrown if the verification failed.
If the verification succeeded a [JWS object](../object/jws.md) is returned and the variable `$signature_index` will contain an integer
that represents the index of the verified signature. **Please note that 0 is a valid index**.

If you have a [JWK object](../object/jwk.md), you can use the method `loadAndVerifySignatureUsingKey` and pass the key as second argument.

# Verification and Detached Payload

If you have a JWS with a detached payload, you will need to use the methods `loadAndVerifySignatureUsingKeyAndDetachedPayload` and `loadAndVerifySignatureUsingKeySetAndDetachedPayload`.
The method calls are similar as the previous calls, except that the encoded payload used to sign has to be passed as an argument.

Example
-------

```php
$jws = $loader->loadAndVerifySignatureUsingKeySetAndDetachedPayload(
    $input,
    $jwk_set,
    ['HS512'],
    $detached_payload,
    $signature_index
);
```

# Unencoded Payload

The verification of the signature is automatically performed depending on the header parameters.

# Signature Index and Security

As explained before, the verified signature index is set in the variable passed as argument.
If the input string contains only signature then this information is not really relevant.
But if there are more than one signature, this information becomes critical, especially for the protected header associated to the signature.

**You must only trust headers from the verified signature pointed by the `$signature_index` variable.**

You will prefer calls that use the `$signature_index` variable:

```php
$jws->getSignature($signature_index)->getProtectedHeader('alg');
```
