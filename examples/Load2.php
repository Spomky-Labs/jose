<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Factory\JWKFactory;
use Jose\Factory\VerifierFactory;
use Jose\Loader;
use Jose\Object\JWKSet;

// In this example, our input is a JWS string in compact serialization format
// See Signature2.php to know to generate such string
$input = '{"signature":"WXfhjDeRv-PCm-5eIgsTkVkUiCXsVe5FODvYjwKHEofZuzJteiNtiDTuSTOKrbsjXIEDbkP8BvYtToZJikjVvw","protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar","123":"ABC"}}';

// The payload is detached. We will use it later
$detached_payload = 'TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg';

// We load the input
$result = Loader::load($input);

// Please not that at this moment the signature and the claims are not verified

// To verify a JWS, we need a JWKSet that contains public keys.
// We create our key object (JWK) using a shared key
$key = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// We create our verifier object with a list of authorized signature algorithms (only 'HS512' in this example)
$verifier = VerifierFactory::createVerifier(
    [
        'HS512'
    ]
);

$is_valid = $verifier->verifyWithKey($result, $key, $detached_payload);

// The variable $is_valid contains a boolean that indicates the signature is valid or not.
// If a claim is not verified (e.g. the JWT expired), an exception is thrown.
