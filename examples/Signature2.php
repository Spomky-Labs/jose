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

use Jose\Factory\KeyFactory;
use Jose\Factory\SignerFactory;
use Jose\JSONSerializationModes;

// We create our key object (JWK) using a shared key
$key = KeyFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// We create a signature instruction.
// The key we created is used for this instruction (first argument).
// We also set the protection header (second argument) that indicates we want a HS512 signature.
// The unprotected header (third argument) contains some custom values.
$instruction = new \Jose\Object\SignatureInstruction(
    $key,
    [
        'alg' => 'HS512',
    ],
    [
        'foo' => 'bar',
        '123' => 'ABC',
    ]
);

// Ou payload is a simple message.
$payload = 'Live long and prosper.';

// We create a signer.
// The first argument is an array of algorithms we will use (we only need 'HS512' for this example).
// The second argument is an array of payload converters. We do not use them for this example.
$signer = SignerFactory::createSigner(
    ['HS512']
);

// Lastly, we sign our claims (first argument) with our instructions (only one instruction).
// We want a JWS in flattened serialization mode (compact serialization mode cannot be used as an unprotected header is set)
// We also want to detach the payload. The result will not contain the payload. The payload will be set into the last argument
$jws = $signer->sign(
    $payload,
    [$instruction],
    JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
    true,
    $detached_payload
);

// Now the variable $jws contains a string with our JWS: {"signature":"WXfhjDeRv-PCm-5eIgsTkVkUiCXsVe5FODvYjwKHEofZuzJteiNtiDTuSTOKrbsjXIEDbkP8BvYtToZJikjVvw","protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar","123":"ABC"}}
// The variable $detached_payload contains our payload (base 64 url safe encoded): TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg
// Please read example Load2.php to know how to load these strings and to verify the signature
