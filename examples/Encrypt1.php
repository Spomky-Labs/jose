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

use Jose\Factory\EncrypterFactory;
use Jose\Factory\KeyFactory;
use Jose\JSONSerializationModes;

// We create our key object (JWK) using a public EC key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = KeyFactory::createFromFile(
    __DIR__.'/../tests/Keys/RSA/public.key',
    null,
    false,
    [
        'kid' => 'My Public RSA key',
        'use' => 'enc',
    ]
);

// We create an encryption instruction.
// The key we created is used for this instruction (first argument).
// We do not need the the sender key (second argument), this key is only mandatory if you use ECDH-ES algorithms.
// The recipient unprotected header (third argument) is an empty array by default.
$instruction = new \Jose\Object\EncryptionInstruction(
    $key
);

// We want to encrypt a very important message
$payload = '8:00PM, train station';

// We create an encrypter.
// The first argument is an array of algorithms we will use (we only need 'RS256' for this example).
// The second argument is an array of payload converters. We do not use them for this example.
// The third parameter is an array of compression methods. By default the 'DEF' (deflate) method is enabled.
$encrypter = EncrypterFactory::createEncrypter(
    [
        'RSA-OAEP-256',  // The algorithm we will use for key encryption
        'A256CBC-HS512', // The algorithm we will use for content encryption
    ]
);

// Lastly, we encrypt our message (first argument) with our instructions (only one instruction).
// We want a JWE in compact serialization mode (most common mode with five parts separated by dots)
// The fourth argument is the protected header. We indicate the algorithms we use and the compression method.
// The compression is not recommend as the payload is very small. Just for the example.
$jwe = $encrypter->encrypt(
    $payload,
    [$instruction],
    JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);

// Now the variable $jwe contains a string with our JWE
// Please read example Load3.php to know how to load this string and to decrypt the content.
