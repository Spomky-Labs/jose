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

class IssuedAtChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('iat')) {
            return [];
        }

        $iat = (int) $jwt->getClaim('iat');
        if (time() < $iat) {
            throw new \Exception('The JWT is issued in the futur.');
        }

        return ['iat'];
    }
}
