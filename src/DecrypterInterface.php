<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSetInterface;

/**
 * Decrypter Interface.
 */
interface DecrypterInterface
{
    /**
     * @param \Jose\Object\JWEInterface $input A JWE object to decrypt
     * @param \Jose\Object\JWKInterface $jwk   The key used to decrypt the input
     *
     * @return bool Returns true if the JWE has been populated with decrypted values, else false.
     */
    public function decryptUsingKey(JWEInterface &$input, JWKInterface $jwk);

    /**
     * @param \Jose\Object\JWEInterface    $input   A JWE object to decrypt
     * @param \Jose\Object\JWKSetInterface $jwk_set The key set used to decrypt the input
     *
     * @return bool Returns true if the JWE has been populated with decrypted values, else false.
     */
    public function decryptUsingKeySet(JWEInterface &$input, JWKSetInterface $jwk_set);
}
