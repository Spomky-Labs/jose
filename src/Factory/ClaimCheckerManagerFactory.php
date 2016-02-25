<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\ClaimChecker\ClaimCheckerInterface;
use Jose\ClaimChecker\ClaimCheckerManager;

final class ClaimCheckerManagerFactory
{
    /**
     * @param string[] $claims
     *
     * @return \Jose\ClaimChecker\ClaimCheckerManagerInterface
     */
    public static function createClaimCheckerManager(array $claims)
    {
        $claim_checker_manager = new ClaimCheckerManager();

        foreach ($claims as $key=>$value) {
            if ($value instanceof ClaimCheckerInterface) {
                $claim_checker_manager->addClaimChecker($value);
            } else {
                if (is_string($key)) {
                    $class = self::getClaimClass($key);
                } else {
                    $class = self::getClaimClass($value);
                }
                $claim_checker_manager->addClaimChecker(new $class($value));
            }
        }

        return $claim_checker_manager;
    }

    /**
     * @param string $claim
     *
     * @return bool
     */
    private static function isClaimSupported($claim)
    {
        return array_key_exists($claim, self::getSupportedClaims());
    }

    /**
     * @param string $claim
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getClaimClass($claim)
    {
        if (true === self::isClaimSupported($claim)) {
            return self::getSupportedClaims()[$claim];
        }
        throw new \InvalidArgumentException(sprintf('Claim "%s" is not supported.', $claim));
    }

    /**
     * @return array
     */
    private static function getSupportedClaims()
    {
        return [
            'aud' => '\Jose\ClaimChecker\AudienceChecker',
            'exp' => '\Jose\ClaimChecker\ExpirationTimeChecker',
            'iat' => '\Jose\ClaimChecker\IssuedAtChecker',
            'nbf' => '\Jose\ClaimChecker\NotBeforeChecker',
        ];
    }
}
