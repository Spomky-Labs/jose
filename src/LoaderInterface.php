<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\JWTInterface;

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
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface|\Jose\Object\JWSInterface[]|\Jose\Object\JWEInterface[]|null If the data has been loaded.
     */
    public function load($input);

    /**
     * Load data and try to return a JWSInterface object, a JWEInterface object or a list of these objects.
     * If the result is a JWE, nothing is decrypted and method `decrypt` must be executed
     * If the result is a JWS, no signature is verified and method `verifySignature` must be executed.
     *
     * @param \Jose\Object\JWEInterface         $input   A JWE object to decrypt
     * @param \Jose\Object\JWKSetInterface|null $jwk_set If not null, use the key set used to verify or decrypt the input, else this method should use a default keys manager.
     *
     * @return bool Returns true if the JWE has been populated with decrypted values, else false.
     */
    public function decrypt(JWEInterface &$input, JWKSetInterface $jwk_set = null);

    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param \Jose\Object\JWSInterface         $input            A JWS object.
     * @param \Jose\Object\JWKSetInterface|null $jwk_set          If not null, the signature will be verified only using keys in the key set, else this method should use a default keys manager
     * @param null|string                       $detached_payload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     *
     * @return bool True if the signature has been verified, else false
     */
    public function verifySignature(JWSInterface $input, JWKSetInterface $jwk_set = null, $detached_payload = null);

    /**
     * Verify the claims of the input.
     * This method must verify if claims are valid or not.
     * For example, if the "exp" header is set and the JWT expired, this method will return false.
     *
     * @param \Jose\Object\JWTInterface $input A JWS object.
     *
     * @return bool True if the JWT has been verified, else false
     */
    public function verify(JWTInterface $input);
}
