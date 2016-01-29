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

use Jose\Factory\EncrypterFactory;
use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;

// We create our key object (JWK) using a public EC key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__ . '/../tests/Unit/Keys/RSA/public.key',
    null,
    [
        'kid' => 'My Public RSA key',
        'use' => 'enc',
    ]
);

// We want to encrypt a very important message
// We define the compression method (DEF) and the algorithm used to encrypt
$jwe = JWEFactory::createJWE(
    '8:00PM, train station',
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);

// We create an encrypter.
// The argument is an array of algorithms we will use (we only need 'RSA-OAEP-256' and 'A256CBC-HS512' for this example).
$encrypter = EncrypterFactory::createEncrypter(
    [
        'RSA-OAEP-256',  // The algorithm we will use for key encryption
        'A256CBC-HS512', // The algorithm we will use for content encryption
    ]
);

// Lastly, we add a recipient for our message.
$jwe = $encrypter->addRecipient($jwe, $key);

// Now the variable $jwe contains our JWE with one recipient
// Please read example Load3.php to know how to load this string and to decrypt the content.
$compact_json = $jwe->toCompactJSON(0);