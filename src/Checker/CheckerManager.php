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

/**
 * Class CheckerManager.
 */
class CheckerManager implements CheckerManagerInterface
{
    /**
     * @var \Jose\ClaimChecker\ClaimCheckerInterface[]
     */
    private $claim_checkers = [];

    /**
     * @var \Jose\ClaimChecker\HeaderCheckerInterface[]
     */
    private $header_checkers = [];

    /**
     * ClaimCheckerManager constructor.
     */
    public function __construct()
    {
        $this->claim_checkers = [
            new ExpirationTimeChecker(),
            new IssuedAtChecker(),
            new NotBeforeChecker(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $checked_claims = [];

        foreach ($this->claim_checkers as $claim_checker) {
            $checked_claims = array_merge(
                $checked_claims,
                $claim_checker->checkClaim($jwt)
            );
        }

        return $checked_claims;
    }

    /**
     * @param \Jose\ClaimChecker\ClaimCheckerInterface $claim_checker
     */
    public function addClaimChecker(ClaimCheckerInterface $claim_checker)
    {
        $this->claim_checkers[] = $claim_checker;
    }

    /**
     * @param \Jose\ClaimChecker\HeaderCheckerInterface $header_checker
     */
    public function addHeaderChecker(HeaderCheckerInterface $header_checker)
    {
        $this->header_checkers[] = $header_checker;
    }
}
