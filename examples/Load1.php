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

use Jose\Checker\IssuedAtChecker;
use Jose\Checker\NotBeforeChecker;
use Jose\Factory\JWKFactory;
use Jose\Factory\VerifierFactory;
use Jose\Loader;
use Jose\Object\JWKSet;

// In this example, our input is a JWS string in compact serialization format
// See Signature1.php to know to generate such string
$input = 'eyJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE0NTE0NjkwMTcsImlhdCI6MTQ1MTQ2OTAxNywiZXhwIjoxNDUxNDcyNjE3LCJpc3MiOiJNZSIsImF1ZCI6IllvdSIsInN1YiI6Ik15IGZyaWVuZCJ9.mplHfnyXzUdlEkPmykForVM0FstqgiihfDRTd2Zd09j6CZzANBJbZNbisLerjO3lR9waRlYvhnZu_ewIAahDwmVTfpSeKKABbAyoTHXTH2WLgMPLtOAsoausUf584eAAj_kyldIOV8a83Qz1NztZHVD3DbGTiCN0BOj-qnc65yQmEDEYK5cxG1xC22YK5aohZ3xm8ixwNZpxYr8cNOkauASYjPGODbHqY_gjQ-aKA21kxbYgwM6mDYSc3QRej1_3m6bD3jKPsK4jv3yzosVMEXOparf4sEb8q_zCPMDJAJgZZ8VICwJdgYnJkQuIutS-w3_iT-riKl8fkgmJezQVkg';

// We load the input
$result = Loader::load($input);

// Now the variable $result contains a JWS object
// You can get headers or claims contained in this object
$result->getSignature(0)->hasProtectedHeader('alg'); // true
$result->getSignature(0)->hasProtectedHeader('alg'); // RS256
$result->getSignature(0)->getProtectedHeaders(); // ['alg'=>'RS256']
$result->hasClaim('foo'); // false
$result->hasClaim('iss'); // true

// Please not that at this moment the signature and the claims are not verified

// To verify a JWS, we need a JWKSet that contains public keys.
// We create our key object (JWK) using a RSA public key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__.'/../tests/Unit/Keys/RSA/public.key',
    null,
    [
        'kid' => 'My public RSA key',
        'use' => 'sig',
    ]
);

// We create our verifier object with a list of authorized signature algorithms (only 'HS512' in this example)
// We add some checkers. These checkers will verify claims or headers.
$verifier = VerifierFactory::createVerifier(
    ['RS256'],
    [
        new IssuedAtChecker(),
        new NotBeforeChecker(),
        //new ExpirationChecker(),
        // You should use Jose\Checker\ExpirationChecker to verify the 'exp' claim
        // We do not use it here because the verification will fail in this example
    ]
);

$is_valid = $verifier->verifyWithKey($result, $key);

// The variable $is_valid contains a boolean that indicates the signature is valid or not.
// If a claim is not verified (e.g. the JWT expired), an exception is thrown.
