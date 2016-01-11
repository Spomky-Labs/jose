<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;

/**
 * Decrypter Interface.
 */
interface DecrypterInterface
{
    /**
     * Load data and try to return a JWSInterface object, a JWEInterface object or a list of these objects.
     * If the result is a JWE, nothing is decrypted and method `decrypt` must be executed
     * If the result is a JWS, no signature is verified and method `verifySignature` must be executed.
     *
     * @param \Jose\Object\JWEInterface    $input   A JWE object to decrypt
     * @param \Jose\Object\JWKSetInterface $jwk_set The key set used to decrypt the input
     *
     * @return bool Returns true if the JWE has been populated with decrypted values, else false.
     */
    public function decrypt(JWEInterface &$input, JWKSetInterface $jwk_set);
}
