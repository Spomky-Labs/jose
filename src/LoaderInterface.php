<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSetInterface;
use Psr\Log\LoggerInterface;

/**
 * Loader Interface.
 */
interface LoaderInterface
{
    /**
     * Load data and try to return a JWSInterface object, a JWEInterface object or a list of these objects.
     * If the result is a JWE (list), nothing is decrypted and method `decrypt` must be executed
     * If the result is a JWS (list), no signature is verified and method `verifySignature` must be executed.
     *
     * @param string $input A string that represents a JSON Web Token message
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface If the data has been loaded.
     */
    public static function load($input);

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKInterface     $jwk
     * @param string[]                      $allowed_algorithms
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, LoggerInterface $logger = null);

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKSetInterface  $jwk_set
     * @param string[]                      $allowed_algorithms
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeySet($input, JWKSetInterface $jwk_set, array $allowed_algorithms, LoggerInterface $logger = null);

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKInterface     $jwk
     * @param string[]                      $allowed_algorithms
     * @param string                        $detached_payload
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeyAndDetachedPayload($input, JWKInterface $jwk, array $allowed_algorithms, $detached_payload, LoggerInterface $logger = null);

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKSetInterface  $jwk_set
     * @param string[]                      $allowed_algorithms
     * @param string                        $detached_payload
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeySetAndDetachedPayload($input, JWKSetInterface $jwk_set, array $allowed_algorithms, $detached_payload, LoggerInterface $logger = null);
}
