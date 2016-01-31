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
     * @return false|int Return false if the JWE has not been decrypted, else an integer that represents the ID of the decrypted recipient
     */
    public function decryptUsingKey(JWEInterface &$input, JWKInterface $jwk);

    /**
     * @param \Jose\Object\JWEInterface    $input   A JWE object to decrypt
     * @param \Jose\Object\JWKSetInterface $jwk_set The key set used to decrypt the input
     *
     * @return false|int Return false if the JWE has not been decrypted, else an integer that represents the ID of the decrypted recipient
     */
    public function decryptUsingKeySet(JWEInterface &$input, JWKSetInterface $jwk_set);
}
