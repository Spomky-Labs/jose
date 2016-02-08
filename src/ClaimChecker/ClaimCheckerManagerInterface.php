<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\ClaimChecker;

use Jose\Object\JWTInterface;

/**
 * Interface ClaimCheckerManagerInterface.
 */
interface ClaimCheckerManagerInterface
{
    /**
     * @param \Jose\Object\JWTInterface $jwt
     *
     * @throws \InvalidArgumentException
     *
     * @return string[]
     */
    public function checkClaims(JWTInterface $jwt);
}
