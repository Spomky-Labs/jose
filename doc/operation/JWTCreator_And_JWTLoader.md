JWT Creator and JWT Loader
=====================

Because you mainly need to deal with JWS and encrypted JWS (as a payload of a JWE) in Compact JSON serialization mode, these two components are made for you.

# JWT Creator

The JWT Creator is available through the `Jose\JWTCreator` class.
This component just needs a [Signer](Sign.md) to be instantiated.

```php
use Jose\JWTCreator;

$jwt_creator = new JWTCreator($signer); // The variable $signer must be a valid Jose\SignerInterface object
```

Then, you will be able to create JWS objects using one single line:

```php
$jws = $jwt_creator->sign(
    $payload,       // The payload to sign
    $headers,       // The protected headers (must contain at least the "alg" parameter)
    $signature_key  // The key used to sign (depends on the "alg" parameter)
);
```

## Encryption Support

If you need to create JWE, then you have to enable the encryption support using a valid Encrypter object.

```php
$jwt_creator->enableEncryptionSupport($encrypter); // The variable $encrypter must be a valid Jose\EncrypterInterface object
```

Now you can create JWE as easily as a JWS:

```php
$jwe = $jwt_creator->encrypt(
    $payload,       // The payload to encrypt
    $headers,       // The shared protected headers (must contain at least the "alg" and "enc" parameters)
    $encryption_key // The key used to encrypt (depends on the "alg" parameter)
);
```

If you want to sign and encrypt at once, then use the following convenient method: `signAndEncrypt`.

```php
$jwe = $jwt_creator->signAndEncrypt(
    $payload,            // The payload to encrypt
    $signature_headers,  // The protected headers (must contain at least the "alg" parameter)
    $signature_key,      // The key used to sign (depends on the "alg" parameter)
    $encryption_headers, // The shared protected headers (must contain at least the "alg" and "enc" parameters)
    $encryption_key      // The key used to encrypt (depends on the "alg" parameter)
);
```

## Other Methods

You also may need to know supported algorithms or if encryption is supported:

* `getSupportedSignatureAlgorithms()`: returns the supported signature algorithms.
* `getSupportedKeyEncryptionAlgorithms()`: returns the supported key encryption algorithms.
* `getSupportedContentEncryptionAlgorithms()`: returns the supported content encryption algorithms.
* `getSupportedCompressionMethods()`: returns the supported compression methods.
* `isEncryptionSupportEnabled()`: returns `true` if the encryption support is enabled or not.


# JWT Loader

The JWT Loader is available through the `Jose\JWTLoader` class.
This component just needs a [Verifier](Verify.md) to be instantiated.

```php
use Jose\JWTLoader;

$jwt_loader = new JWTLoader($verifier); // The variable $verifier must be a valid Jose\VerifierInterface object
```

Then, you will be able to load JWS objects using one single line:

```php
$jws = $jwt_loader->load(
    $input, // The JWS string you want to load
);
```


If the method succeeded, the `$jws` variable will contain a valid `Jose\JWSInterface` object.
*Note that the method `load` will always return a JWS or an exception will be thrown.*

The resulting JWS is not yet verified. You MUST check the signature and claims (if available):

```php
$index = $jwt_loader->verify(
    $jws,    // The JWS object
    $key_set // A Jose\JWKSetInterface object that contains public keys
);
```

The variable `$index` contains the index of the verified signature 

If the JWS you want to verify has a detached payload, then set the detached payload as the third argument:

```php
$index = $jwt_loader->verify(
    $jws,             // The JWS object
    $key_set          // A Jose\JWKSetInterface object that contains public keys
    $detached_payload // The detached payload
);
```

## Decryption Support

If you need to load an encrypted JWS (JWS as payload of a JWE), then you have to enable the decryption support using a valid Decrypter object.

```php
$jwt_loader->enableDecryptionSupport($decrypter); // The variable $decrypter must be a valid Jose\DecrypterInterface object
```

The method to call is the same as previously shown, but you have to set a JWKSet object as second argument.
This JWKSet object mut contain private keys or shared keys used to decrypt the input.

```php
$jws = $jwt_loader->load(
    $input,  // The JWS or JWE string you want to load
    $jwk_set // The JWKSet object
);
```

If an encrypted JWS is expected, then you can set the third argument as `true`:

```php
$jws = $jwt_loader->load(
    $input,   // The JWE string you want to load
    $jwk_set, // The JWKSet object
    true      // The input must be an encrypted JWS (JWS as payload of a JWE) else an exception will be thrown
);
```

## Other Methods

You also may need to know supported algorithms or if decryption is supported:

* `getSupportedSignatureAlgorithms()`: returns the supported signature algorithms.
* `getSupportedKeyDecryptionAlgorithms()`: returns the supported key decryption algorithms.
* `getSupportedContentDecryptionAlgorithms()`: returns the supported content decryption algorithms.
* `getSupportedCompressionMethods()`: returns the supported compression methods.
* `isDecryptionSupportEnabled()`: returns `true` if the decryption support is enabled or not.
