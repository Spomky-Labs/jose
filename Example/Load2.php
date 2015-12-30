<?php

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Factory\KeyFactory;
use Jose\Factory\LoaderFactory;
use Jose\Factory\VerifierFactory;
use Jose\Object\JWKSet;

// In this example, our input is a JWS string in compact serialization format
// See Signature2.php to know to generate such string
$input = '{"signature":"WXfhjDeRv-PCm-5eIgsTkVkUiCXsVe5FODvYjwKHEofZuzJteiNtiDTuSTOKrbsjXIEDbkP8BvYtToZJikjVvw","protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar","123":"ABC"}}';

// The payload is detached. We will use it later
$detached_payload = 'TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg';

// We create a loader.
// The first argument is an array of payload converters. We do not use them for this example.
$loader = LoaderFactory::createLoader();

// We load the input
$result = $loader->load($input);

// Please not that at this moment the signature and the claims are not verified

// To verify a JWS, we need a JWKSet that contains public keys.
// We create our key object (JWK) using a shared key
$key = KeyFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// Then we set this key in a keyset (JWKSet object)
// Be careful, the JWKSet object is immutable. When you add a key, you get a new JWKSet object.
$keyset = new JWKSet();
$keyset = $keyset->addKey($key);

// We create our verifier object with a list of authorized signature algorithms (only 'HS512' in this example)
$verifier = VerifierFactory::createVerifier(
    ['HS512']
);

$is_valid = $verifier->verify($result, $keyset, $detached_payload);

// The variable $is_valid contains a boolean that indicates the signature is valid or not.
// If a claim is not verified (e.g. the JWT expired), an exception is thrown.
