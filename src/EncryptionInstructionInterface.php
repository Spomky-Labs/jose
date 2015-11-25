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

/**
 * Encryption Instruction Interface.
 *
 * This interface is required by the Encrypter Interface to encrypt payloads and create a JWE.
 */
interface EncryptionInstructionInterface
{
    /**
     * The key used to encrypt the payload.
     *
     * @return \Jose\JWKInterface
     */
    public function getRecipientKey();

    /**
     * The key of the sender. This key is only needed when using some algorithm that require it (e.g. agreement key algorithm such as ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW).
     *
     * @return \Jose\JWKInterface|null
     */
    public function getSenderKey();

    /**
     * Unprotected header set for this recipient only.
     *
     * @return array
     */
    public function getRecipientUnprotectedHeader();
}
