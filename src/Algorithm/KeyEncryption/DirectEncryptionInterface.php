<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Jose\Algorithm\EncryptionInterface;
use Jose\JWKInterface;

/**
 *
 */
interface DirectEncryptionInterface extends EncryptionInterface
{
    /**
     * @param \Jose\JWKInterface $key    The key used to get the CEK
     * @param array              $header The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The CEK
     */
    public function getCEK(JWKInterface $key, array $header);
}
