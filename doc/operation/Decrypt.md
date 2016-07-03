Decrypt a JWE
=============

This library provides a `Loader` object able to load and decrypt the payload of a JWE.

# The Common Way

To decrypt a JWE, you will need:

* the JWE string (Compact, Flattened or in General JSON Representation Mode),
* a symmetric key, a private key ([JWK object](../object/jwk.md)) or a key set ([JWKSet object](../object/jwkset.md)),
* the `Loader` object,
* a list of algorithms allowed to be used.

```php
use Jose\Factory\JWKFactory;
use Jose\Loader;

// We load our private RSA key.
$key1 = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/private.encrypted.key',
    'Password',
    [
        'kid' => 'My Private RSA key',
        'use' => 'enc',
        'alg' => 'RSA-OAEP',
    ]
);

// We create our loader.
$loader = new Loader();

// This is the input we want to load verify.
$input = 'eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0.rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs.-nBoKLH0YkLZPSI9.o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw.UCGiqJxhBI3IFVdPalHHvA';

// The payload is decrypted using our key.
$jws = $loader->loadAndDecryptUsingKey(
    $input,            // The input to load and decrypt
    $jwk,              // The symmetric or private key 
    ['RSA-OAEP'],      // A list of allowed key encryption algorithms
    ['A256GCM'],       // A list of allowed content encryption algorithms
    $recipient_index   // If decrypted, this variable will be set with the recipient index used to decrypt
);
```

An exception is thrown if the decryption failed.

If the verification succeeded a [JWE object](../object/jwe.md) is returned and the variable `$recipient_index` will contain an integer
that represents the index of the decrypted content encryption key. **Please note that 0 is a valid index**.
The variable `$recipient_index` needed to get the recipient unprotected header.

```php
$jwe->getRecipient($recipient_index)->getHeader('alg');
```

If you have a [JWKSet object](../object/jwkset.md), you can use the method `loadAndDecryptUsingKeySet` and pass the key set as second argument.
