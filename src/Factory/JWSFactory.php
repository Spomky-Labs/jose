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

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Object\JWKInterface;
use Jose\Object\JWS;
use Jose\Signer;
use Psr\Log\LoggerInterface;

final class JWSFactory
{
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

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param array                         $protected_headers
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return string
     */
    public static function createJWSToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers, LoggerInterface $logger = null)
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, [], $logger);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param array                         $protected_headers
     * @param string                        $encoded_payload
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWKInterface $signature_key, &$encoded_payload, array $protected_headers, LoggerInterface $logger = null)
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $encoded_payload, $protected_headers, [], $logger);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param array                         $protected_headers
     * @param array                         $headers
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return string
     */
    public static function createJWSToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [], LoggerInterface $logger = null)
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, $headers, $logger);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param string                        $encoded_payload
     * @param array                         $protected_headers
     * @param array                         $headers
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWKInterface $signature_key, &$encoded_payload, array $protected_headers = [], $headers = [], LoggerInterface $logger = null)
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $encoded_payload, $protected_headers, $headers, $logger);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param array                         $protected_headers
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function createJWSAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [], LoggerInterface $logger = null)
    {
        $jws = self::createJWS($payload);

        $jws = $jws->addSignature($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']], $logger);
        $signer->sign($jws);

        return $jws;
    }

    /**
     * @param mixed                         $payload
     * @param \Jose\Object\JWKInterface     $signature_key
     * @param string                        $encoded_payload
     * @param array                         $protected_headers
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function createJWSWithDetachedPayloadAndSign($payload, JWKInterface $signature_key, &$encoded_payload, array $protected_headers = [], $headers = [], LoggerInterface $logger = null)
    {
        $jws = self::createJWSWithDetachedPayload($payload, $encoded_payload);

        $jws = $jws->addSignature($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']], $logger);
        $signer->signWithDetachedPayload($jws, $encoded_payload);

        return $jws;
    }
}
