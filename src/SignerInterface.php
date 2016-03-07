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
     * @param null|string               $detached_payload
     */
    public function signWithDetachedPayload(JWSInterface &$jws, $detached_payload);

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    public function sign(JWSInterface &$jws);
}
