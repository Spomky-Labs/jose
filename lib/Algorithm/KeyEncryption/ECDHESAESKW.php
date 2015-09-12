<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementWrappingInterface;

/**
 * Class ECDHESAESKW.
 */
abstract class ECDHESAESKW implements KeyAgreementWrappingInterface
{
    /**
     *
     */
    public function __construct()
    {
        if (!trait_exists('\AESKW\AESKW')) {
            throw new \RuntimeException("The library 'spomky-labs/aes-key-wrap' is required to use Key Wrap based algorithms");
        }
    }

    /**
     * @param \Jose\JWKInterface $sender_key
     * @param \Jose\JWKInterface $receiver_key
     * @param string             $cek
     * @param int                $encryption_key_length
     * @param array              $complete_header
     * @param array              $additional_header_values
     *
     * @return string
     */
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array $complete_header, array &$additional_header_values)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $sender_key, $receiver_key, $complete_header, $additional_header_values);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    /**
     * @param \Jose\JWKInterface $receiver_key
     * @param string             $encrypted_cek
     * @param int                $encryption_key_length
     * @param array              $complete_header
     *
     * @return string
     */
    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $complete_header)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $receiver_key, null, $complete_header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @return mixed
     */
    abstract protected function getWrapper();
}
