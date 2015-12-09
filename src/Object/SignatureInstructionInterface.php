<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Signature Instruction Interface.
 *
 * This interface is required by the SignerInterface to signed payloads and create a JWS.
 */
interface SignatureInstructionInterface
{
    /**
     * The private key used to sign the payload.
     *
     * @return \Jose\Object\JWKInterface
     */
    public function getKey();

    /**
     * The protected header associated with the signature.
     *
     * @return array
     */
    public function getProtectedHeader();

    /**
     * The unprotected header associated with the signature.
     *
     * @return array
     */
    public function getUnprotectedHeader();
}
