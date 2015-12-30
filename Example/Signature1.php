<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Factory\KeyFactory;
use Jose\Factory\SignerFactory;
use Jose\JSONSerializationModes;

// We create our key object (JWK) using an encrypted RSA key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = KeyFactory::createFromFile(
    __DIR__.'/../tests/Keys/RSA/private.encrypted.key',
    'tests',
    false,
    [
        'kid' => 'My Private RSA key',
        'use' => 'sig',
    ]
);

// We create a signature instruction.
// The key we created is used for this instruction (first argument).
// We also set the protection header (second argument) that indicates we want a RS256 signature.
// There is no unprotected header (third argument is an empty array by default).
$instruction = new \Jose\Object\SignatureInstruction(
    $key,
    [
        'alg' => 'RS256',
    ]
);

// We create an array of claims.
// This array wil be the payload of the JWS
$claims = [
    'nbf' => time(),
    'iat' => time(),
    'exp' => time() + 3600,
    'iss' => 'Me',
    'aud' => 'You',
    'sub' => 'My friend',
];

// We create a signer.
// The first argument is an array of algorithms we will use (we only need 'RS256' for this example).
// The second argument is an array of payload converters. We do not use them for this example.
$signer = SignerFactory::createSigner(
    ['RS256']
);

// Lastly, we sign our claims (first argument) with our instructions (only one instruction).
// We want a JWS in compact serialization mode (most common mode with three parts separated by dots)
$jws = $signer->sign(
    $claims,
    [$instruction],
    JSONSerializationModes::JSON_COMPACT_SERIALIZATION
);

// Now the variable $jws contains a string with our JWS
// Please read example Load1.php to know how to load this string and to verify the signature
