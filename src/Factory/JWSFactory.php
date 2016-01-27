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

use Base64Url\Base64Url;
use Jose\Object\JWS;

final class JWSFactory
{
    /**
     * JWSFactory constructor.
     *
     * This factory is not supposed to be instantiated
     */
    private function __construct()
    {
    }

    /**
     * @param mixed $payload
     *
     * @return \Jose\Object\JWSInterface
     */
    public static function createJWS($payload)
    {
        $jws = new JWS();
        $jws = $jws->withPayload($payload);

        return $jws;
    }

    /**
     * @param mixed  $payload
     * @param string $encoded_payload
     *
     * @return \Jose\Object\JWSInterface
     */
    public static function createJWSWithDetachedPayload($payload, &$encoded_payload)
    {
        $encoded_payload = Base64Url::encode(is_string($payload) ? $payload : json_encode($payload));

        return new JWS();
    }
}
