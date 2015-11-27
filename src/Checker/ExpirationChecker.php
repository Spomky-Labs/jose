<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Jose\JWTInterface;

final class ExpirationChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $exp = $jwt->getExpirationTime();
        if (null !== $exp && time() > $exp) {
            throw new \Exception('The JWT has expired.');
        }
    }
}
