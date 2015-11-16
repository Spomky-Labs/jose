<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

interface CheckerInterface
{
    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception If verification failed
     *
     * @return self
     */
    public function checkJWT(JWTInterface $jwt);
}
