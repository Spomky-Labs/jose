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

class ExpirationTimeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('exp')) {
            return [];
        }

        $exp = (int) $jwt->getClaim('exp');
        if (time() > $exp) {
            throw new \InvalidArgumentException('The JWT has expired.');
        }

        return ['exp'];
    }
}
