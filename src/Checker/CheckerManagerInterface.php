<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Jose\Object\JWEInterface;
use Jose\Object\JWSInterface;

/**
 * Interface CheckerManagerInterface.
 */
interface CheckerManagerInterface
{
    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param int                       $signature
     */
    public function checkJWS(JWSInterface $jws, $signature);

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param int                       $recipient
     */
    public function checkJWE(JWEInterface $jwe, $recipient);
}
