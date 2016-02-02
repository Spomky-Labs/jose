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

interface ClaimCheckerManagerInterface
{
    /**
     * @param \Jose\Checker\ClaimCheckerInterface $checker
     */
    public function addChecker(ClaimCheckerInterface $checker);

    /**
     * @param \Jose\Object\JWTInterface $jwt
     *
     * @throws \Exception If verification failed
     */
    public function checkJWT(JWTInterface $jwt);
}
