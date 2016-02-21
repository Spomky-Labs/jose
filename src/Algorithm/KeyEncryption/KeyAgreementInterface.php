<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Object\JWKInterface;

/**
 *
 */
interface KeyAgreementInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * @param int                       $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param string                    $algorithm                The algorithm
     * @param \Jose\Object\JWKInterface $private_key              Private key (sender key or receiver key depending on operation to execute
     * @param \Jose\Object\JWKInterface $public_key               Public key (receiver key on encryption) or null if key is in the header
     * @param array                     $complete_header          The complete header of the JWT
     * @param array                     $additional_header_values Set additional header values if needed
     *
     * @return mixed
     */
    public function getAgreementKey($encryption_key_length, $algorithm, JWKInterface $private_key, JWKInterface $public_key = null, array $complete_header = [], array &$additional_header_values = []);
}
