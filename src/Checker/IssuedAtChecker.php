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

final class IssuedAtChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('iat')) {
            return;
        }
        $iat = (int) $jwt->getClaim('iat');
        if (time() < $iat) {
            throw new \Exception('The JWT is issued in the futur.');
        }
    }
}
