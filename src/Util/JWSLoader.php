<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Base64Url\Base64Url;
use Jose\Object\JWS;
use Jose\Object\JWSInterface;

final class JWSLoader
{
    /**
     * @param array $data
     *
     * @return \Jose\Object\JWSInterface
     */
    public static function loadSerializedJsonJWS(array $data)
    {
        $jws = new JWS();

        self::populatePayload($jws, $data);

        foreach ($data['signatures'] as $signature) {
            $bin_signature = Base64Url::decode($signature['signature']);
            $protected_headers = self::getProtectedHeaders($signature);
            $headers = self::getHeaders($signature);

            $jws = $jws->addSignature(null, $protected_headers, $headers, $bin_signature);
        }

        return $jws;
    }

    /**
     * @param array $data
     *
     * @return array
     */
    private static function getProtectedHeaders(array $data)
    {
        if (array_key_exists('protected', $data)) {
            return json_decode(Base64Url::decode($data['protected']), true);
        }

        return [];
    }

    /**
     * @param array $data
     *
     * @return array
     */
    private static function getHeaders(array $data)
    {
        if (array_key_exists('header', $data)) {
            return $data['header'];
        }

        return [];
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param array                     $data
     */
    private static function populatePayload(JWSInterface &$jws, array $data)
    {
        if (array_key_exists('payload', $data)) {
            $payload = Base64Url::decode($data['payload']);
            $json = json_decode($payload, true);
            if (null !== $json && !empty($payload)) {
                $payload = $json;
            }
            $jws = $jws->withPayload($payload);
        }
    }
}
