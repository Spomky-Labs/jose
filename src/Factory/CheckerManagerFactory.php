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

use Jose\Checker\ClaimCheckerInterface;
use Jose\Checker\CheckerManager;
use Jose\Checker\HeaderCheckerInterface;

final class CheckerManagerFactory
{
    /**
     * @param string[] $claims
     * @param string[] $headers
     *
     * @return \Jose\Checker\CheckerManagerInterface
     */
    public static function createClaimCheckerManager(array $claims = ['exp', 'iat', 'nbf'], array $headers = ['crit'])
    {
        $claim_checker_manager = new CheckerManager();

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

        foreach ($headers as $key=>$value) {
            if ($value instanceof HeaderCheckerInterface) {
                $claim_checker_manager->addHeaderChecker($value);
            } else {
                if (is_string($key)) {
                    $class = self::getHeaderClass($key);
                } else {
                    $class = self::getHeaderClass($value);
                }
                $claim_checker_manager->addHeaderChecker(new $class($value));
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
     * @param string $header
     *
     * @return bool
     */
    private static function isHeaderSupported($header)
    {
        return array_key_exists($header, self::getSupportedHeaders());
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
     * @param string $header
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getHeaderClass($header)
    {
        if (true === self::isHeaderSupported($header)) {
            return self::getSupportedHeaders()[$header];
        }
        throw new \InvalidArgumentException(sprintf('Header "%s" is not supported.', $header));
    }

    /**
     * @return array
     */
    private static function getSupportedClaims()
    {
        return [
            'aud' => '\Jose\Checker\AudienceChecker',
            'exp' => '\Jose\Checker\ExpirationTimeChecker',
            'iat' => '\Jose\Checker\IssuedAtChecker',
            'nbf' => '\Jose\Checker\NotBeforeChecker',
        ];
    }

    /**
     * @return array
     */
    private static function getSupportedHeaders()
    {
        return [
            'crit' => '\Jose\Checker\CriticalHeaderChecker',
        ];
    }
}
