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
     * @param \Jose\Object\JWEInterface $input           A JWE object to decrypt
     * @param \Jose\Object\JWKInterface $jwk             The key used to decrypt the input
     * @param null|int                  $recipient_index If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     */
    public function decryptUsingKey(JWEInterface &$input, JWKInterface $jwk, &$recipient_index = null);

    /**
     * @param \Jose\Object\JWEInterface    $input           A JWE object to decrypt
     * @param \Jose\Object\JWKSetInterface $jwk_set         The key set used to decrypt the input
     * @param null|int                     $recipient_index If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     */
    public function decryptUsingKeySet(JWEInterface &$input, JWKSetInterface $jwk_set, &$recipient_index = null);
}
