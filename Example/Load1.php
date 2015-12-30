<?php

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Checker\ExpirationChecker;
use Jose\Checker\IssuedAtChecker;
use Jose\Checker\NotBeforeChecker;
use Jose\Factory\KeyFactory;
use Jose\Factory\LoaderFactory;
use Jose\Factory\VerifierFactory;
use Jose\Object\JWKSet;

// In this example, our input is a JWS string in compact serialization format
// See Signature1.php to know to generate such string
$input = 'eyJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE0NTE0NjkwMTcsImlhdCI6MTQ1MTQ2OTAxNywiZXhwIjoxNDUxNDcyNjE3LCJpc3MiOiJNZSIsImF1ZCI6IllvdSIsInN1YiI6Ik15IGZyaWVuZCJ9.mplHfnyXzUdlEkPmykForVM0FstqgiihfDRTd2Zd09j6CZzANBJbZNbisLerjO3lR9waRlYvhnZu_ewIAahDwmVTfpSeKKABbAyoTHXTH2WLgMPLtOAsoausUf584eAAj_kyldIOV8a83Qz1NztZHVD3DbGTiCN0BOj-qnc65yQmEDEYK5cxG1xC22YK5aohZ3xm8ixwNZpxYr8cNOkauASYjPGODbHqY_gjQ-aKA21kxbYgwM6mDYSc3QRej1_3m6bD3jKPsK4jv3yzosVMEXOparf4sEb8q_zCPMDJAJgZZ8VICwJdgYnJkQuIutS-w3_iT-riKl8fkgmJezQVkg';

// We create a loader.
// The first argument is an array of payload converters. We do not use them for this example.
$loader = LoaderFactory::createLoader();

// We load the input
$result = $loader->load($input);

// Now the variable $result contains a JWS object
// You can get headers or claims contained in this object
$result->hasHeader('alg'); // true
$result->getHeader('alg'); // RS256
$result->getHeaders(); // ['alg'=>'RS256']
$result->hasClaim('foo'); // false
$result->hasClaim('iss'); // true

// Please not that at this moment the signature and the claims are not verified

// To verify a JWS, we need a JWKSet that contains public keys.
// We create our key object (JWK) using a RSA public key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = KeyFactory::createFromFile(
    __DIR__.'/../tests/Keys/RSA/public.key',
    null,
    false,
    [
        'kid' => 'My public RSA key',
        'use' => 'sig',
    ]
);

// Then we set this key in a keyset (JWKSet object)
// Be careful, the JWKSet object is immutable. When you add a key, you get a new JWKSet object.
$keyset = new JWKSet();
$keyset = $keyset->addKey($key);

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

$is_valid = $verifier->verify($result, $keyset);

// The variable $is_valid contains a boolean that indicates the signature is valid or not.
// If a claim is not verified (e.g. the JWT expired), an exception is thrown.
