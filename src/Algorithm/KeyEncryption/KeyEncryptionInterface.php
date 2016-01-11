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

use Jose\Algorithm\EncryptionInterface;
use Jose\Object\JWKInterface;

/**
 *
 */
interface KeyEncryptionInterface extends EncryptionInterface
{
    /**
     * Encrypt the CEK.
     *
     * @param \Jose\Object\JWKInterface $key    The key used to wrap the CEK
     * @param string                    $cek    The CEK to encrypt
     * @param array                     $header The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The encrypted CEK
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header);

    /**
     * Decrypt de CEK.
     *
     * @param \Jose\Object\JWKInterface $key          The key used to wrap the CEK
     * @param string                    $encryted_cek The CEK to decrypt
     * @param array                     $header       The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The decrypted CEK
     */
    public function decryptKey(JWKInterface $key, $encryted_cek, array $header);
}
