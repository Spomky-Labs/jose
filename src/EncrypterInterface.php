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

/**
 * Encrypter Interface.
 */
interface EncrypterInterface
{
    /**
     * @param \Jose\Object\JWEInterface $jwe
     */
    public function encrypt(JWEInterface &$jwe);
}
