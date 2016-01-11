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

/**
 * Encrypter Interface.
 */
interface EncrypterInterface
{
    /**
     * Encrypt an input and convert it into a JWE JSON (Compact/Flattened) Serialized representation.
     *
     * To encrypt the input using different algorithms, the "alg" parameter must be set in the unprotected header of the $instruction.
     * Please note that this is not possible when using the algorithms "dir" or "ECDH-ES".
     *
     * @param \Jose\Object\JWTInterface|\Jose\Object\JWKInterface|\Jose\Object\JWKSetInterface|array|string $input                     A JWKInterface/JWKInterface/JWKSetInterface object
     * @param \Jose\Object\EncryptionInstructionInterface[]                                                 $instructions              A list of instructions used to encrypt the input
     * @param array                                                                                         $shared_protected_header   Shared protected headers. If the input is a JWTInterface object, this parameter is merged with the protected header of the input.
     * @param array                                                                                         $shared_unprotected_header Shared unprotected headers. If the input is a JWTInterface object, this parameter is merged with the unprotected header of the input.
     * @param string                                                                                        $serialization             Serialization method.
     * @param string|null                                                                                   $aad                       Additional Authentication Data. This parameter is useless if the serialization is JSON_COMPACT_SERIALIZATION.
     *
     * @throws \Exception
     *
     * @return string|string[] The JSON (Compact/Flattened) Serialized representation
     */
    public function encrypt($input, array $instructions, $serialization, array $shared_protected_header = [], array $shared_unprotected_header = [], $aad = null);
}
