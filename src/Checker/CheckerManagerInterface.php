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

use Jose\Object\JWTInterface;

interface CheckerManagerInterface
{
    /**
     * @param \Jose\Checker\CheckerInterface $checker
     */
    public function addChecker(CheckerInterface $checker);

    /**
     * @param \Jose\Object\JWTInterface $jwt
     *
     * @throws \Exception If verification failed
     */
    public function checkJWT(JWTInterface $jwt);
}
