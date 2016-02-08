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
 * Class ClaimCheckerManager
 */
class ClaimCheckerManager implements ClaimCheckerManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaims(JWTInterface $jwt)
    {
        $checkers = $this->getSupportedClaimCheckers();
        $checked_claims = [];

        foreach ($checkers as $checker) {
            $checked_claims = array_merge(
                $checked_claims,
                $checker->checkClaim($jwt)
            );
        }

        return $checked_claims;
    }

    /**
     * @return \Jose\ClaimChecker\ClaimCheckerInterface[]
     */
    protected function getSupportedClaimCheckers()
    {
        return [
            new ExpirationTimeChecker(),
            new IssuedAtChecker(),
            new NotBeforeChecker(),
        ];
    }
}
