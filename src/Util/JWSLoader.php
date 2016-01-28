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
use Jose\Object\Signature;
use Jose\Object\SignatureInterface;

final class JWSLoader
{
    /**
     * Loader constructor.
     */
    private function __construct()
    {
    }

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
            $object = new Signature();
            $object = $object->withSignature(Base64Url::decode($signature['signature']));

            self::populateProtectedHeaders($object, $signature);
            self::populateHeaders($object, $signature);

            $jws = $jws->addSignature($object);
        }

        return $jws;
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     * @param array                           $data
     */
    private static function populateProtectedHeaders(SignatureInterface &$signature, array $data)
    {
        if (array_key_exists('protected', $data)) {
            $signature = $signature->withEncodedProtectedHeaders($data['protected']);
        }
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     * @param array                           $data
     */
    private static function populateHeaders(SignatureInterface &$signature, array $data)
    {
        if (array_key_exists('header', $data)) {
            $signature = $signature->withHeaders($data['header']);
        }
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
