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

use Jose\Factory\DecrypterFactory;
use Jose\Factory\JWKFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;

/******************/
/*   INPUT DATA   */
/******************/

// My direct key.
$shared_key = JWKFactory::createFromValues([
    'kty' => 'dir',
    'dir' => 'saH0gFSP4XM_tAP_a5rU9ooHbltwLiJpL4LLLnrqQPw',
]);

//The JWE
$input = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiTXkgU2hhcmVkIEtleSJ9..gqkq-9muWfQd3AHD.kg_fCtrkId7poGRCUP9ARO4KQ4m0R6lU5rwNS8Mm8nLFMy_X3nBC1VkL_zDehO4K6eEliZ9ISBEE7fFM6aFppfTCwFd_q-qikoOy7zsSeOOEawDZX2qMMdZYnaZs1HZTezdgS7HmoNK1J1TfE1PNrmhjrIZEbTANWw.Hxy5fTBX8X10_bz5UuDeBQ';

/******************/
/*    DECRYPTER   */
/******************/

// The decrypter will try to decrypt a JWE object using private, shared or direct keys in the keyset
// We indicate the algorithms we want to use
$decrypter = DecrypterFactory::createDecrypter(
    [
        'dir',
        'A256GCM',
    ]
);

/******************/
/*    LET'S GO!   */
/******************/

// We load the input
$jwe = Loader::load($input);

if (!$jwe instanceof JWEInterface) {
    throw new \RuntimeException('Something went wrong');
}

// At this time the payload is null.
// We have to decrypt it
$is_decrypted = $decrypter->decryptUsingKey($jwe, $shared_key);

// The variable $is_decrypted contains a boolean that indicates the decryption succeeded or not.
// Now the $jwe object has a payload
