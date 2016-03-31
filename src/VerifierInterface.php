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
use Jose\Object\JWSInterface;

/**
 * Verifier Interface.
 */
interface VerifierInterface
{
    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param \Jose\Object\JWSInterface $input            A JWS object.
     * @param \Jose\Object\JWKInterface $jwk              The signature will be verified using keys in the key set
     * @param null|string               $detached_payload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param null|int                  $recipient_index  If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKey(JWSInterface $input, JWKInterface $jwk, $detached_payload = null, &$recipient_index = null);

    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param \Jose\Object\JWSInterface    $input            A JWS object.
     * @param \Jose\Object\JWKSetInterface $jwk_set          The signature will be verified using keys in the key set
     * @param null|string                  $detached_payload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param null|int                     $recipient_index  If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKeySet(JWSInterface $input, JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null);
}
