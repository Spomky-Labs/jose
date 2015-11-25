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
 * Signer Interface.
 */
interface SignerInterface
{
    /**
     * Sign an input and convert it into JWS JSON (Compact/Flattened) Serialized representation.
     *
     * @param \Jose\JWTInterface|\Jose\JWKInterface|\Jose\JWKSetInterface|string|array $input              A JWKInterface/JWKInterface/JWKSetInterface object
     * @param \Jose\SignatureInstructionInterface[]                                    $instructions       A list of instructions used to encrypt the input
     * @param string                                                                   $serialization      Serialization method. If the argument $keys contains more than one private key and value is JSON_COMPACT_SERIALIZATION or JSON_FLATTENED_SERIALIZATION, the result will be an array of JWT.
     * @param bool                                                                     $detached_signature If true, the payload will be detached and variable $detached_payload will be set
     * @param null|string                                                              $detached_payload   The detached payload encoded in Base64 URL safe
     *
     * @throws \Exception
     *
     * @return string|string[] The JSON (Compact/Flattened) Serialized representation
     */
    public function sign($input, array $instructions, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $detached_signature = false, &$detached_payload = null);
}
