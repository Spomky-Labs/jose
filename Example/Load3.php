<?php

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Factory\KeyFactory;
use Jose\Factory\LoaderFactory;
use Jose\Factory\DecrypterFactory;
use Jose\Object\JWKSet;

// In this example, our input is a JWE string in compact serialization format
// See Encrypt1.php to know to generate such string
$input = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiREVGIn0.ZiRhxN_ED1Ed494P85l6p_cwjbS3vkY_qUqsVKnKROGBJVLtyLGKTUgH8PF3wT4WJZlsw8hze_RLf_4ryojuVBMiaJ4wqVLupOH_X00LdKN5ggVeJNiXhu7okpH0osPyWycwlkaH8cAYOA2MUFOZUw8ZvReZULZPswWKnCA7y-yCig0BjTE3WA8B8f66ccPjyK9OYOUGw27L8qD7f5F4goeHiPVpvg_Fb3Se8vD2XzY5m29QsV3TWKu34sHQvbBTVqOlOZ0WdXn11jGZUkg6clYc5iNAWt7qRkk6baGz2lg7DZH2ErK0bFRxjEzhL9qpSkhCMurM4i6E5iDQVLb8rA.wxOu_E6b36tlckgkfXZ6iw.GPjZCuq1rZfEE-L8XW3jh0evjaDPyIkpymI6wvIuGJM.XK-Z-_BbYbDDeUf69dThSNHdITqaF-bM1EVakK4e9yg';

// We create a loader.
// The first argument is an array of payload converters. We do not use them for this example.
$loader = LoaderFactory::createLoader();

// We load the input
$result = $loader->load($input);

// Now the variable $result contains a JWE object
// At this moment, you can get headers but the payload is still encrypted.
// The call $result->getPayload() will return null

// To decrypt and verify our JWE, we need a JWKSet that contains private keys.
// We create our key object (JWK) using an encrypted RSA key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = KeyFactory::createFromFile(
    __DIR__.'/../tests/Keys/RSA/private.encrypted.key',
    'tests',
    false,
    [
        'kid' => 'My private RSA key',
        'use' => 'enc',
    ]
);

// Then we set this key in a keyset (JWKSet object)
// Be careful, the JWKSet object is immutable. When you add a key, you get a new JWKSet object.
$keyset = new JWKSet();
$keyset = $keyset->addKey($key);

// We create our decrypter object with a list of authorized signature algorithms (only 'RSA-OAEP-256' and 'A256CBC-HS512' in this example)
// We do not add
// * Payload converters (second argument).
// * The third argument (enabled compression methods) is ['DEF'] by default.
// * We do not add checkers (fourth argument).
$decrypter = DecrypterFactory::createDecrypter(
    [
        'RSA-OAEP-256',
        'A256CBC-HS512',
    ]
);

$is_decrypted = $decrypter->decrypt($result, $keyset);

// The variable $is_decrypted contains a boolean that indicates the decryption succeeded or not.
// If a claim is not verified (e.g. the JWT expired), an exception is thrown.
