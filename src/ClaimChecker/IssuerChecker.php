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

abstract class IssuerChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('iss')) {
            return [];
        }

        $issuer = $jwt->getClaim('iss');
        if (!$this->isIssuerAllowed($issuer)) {
            throw new \InvalidArgumentException(sprintf('The issuer "%s" is not allowed.', $issuer));
        }

        return ['iss'];
    }

    /**
     * @param string $issuer
     *
     * @return bool
     */
    abstract protected function isIssuerAllowed($issuer);
}
