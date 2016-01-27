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
use Jose\Object\JWSInterface;

/**
 * Signer Interface.
 */
interface SignerInterface
{
    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param \Jose\Object\JWKInterface $key
     * @param null|string               $detached_payload
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignatureWithDetachedPayload(JWSInterface $jws, JWKInterface $key, $detached_payload, array $protected_headers = [], array $headers = []);

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param \Jose\Object\JWKInterface $key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignature(JWSInterface $jws, JWKInterface $key, array $protected_headers = [], array $headers = []);
}
