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

use Jose\Object\JWE;

final class JWEFactory
{
    /**
     * JWEFactory constructor.
     *
     * This factory is not supposed to be instantiated
     */
    private function __construct()
    {
    }

    /**
     * @param mixed       $payload
     * @param array       $shared_protected_headers
     * @param array       $shared_headers
     * @param null|string $aad
     *
     * @return \Jose\Object\JWEInterface
     */
    public static function createJWE($payload, array $shared_protected_headers = [], array $shared_headers = [], $aad = null)
    {
        $jwe = new JWE();
        $jwe = $jwe->withSharedProtectedHeaders($shared_protected_headers);
        $jwe = $jwe->withSharedHeaders($shared_headers);
        $jwe = $jwe->withPayload($payload);

        if (null !== $aad) {
            $jwe = $jwe->withAAD($aad);
        }

        return $jwe;
    }
}
