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

use Jose\Object\JWKInterface;

/**
 * Class ECDHESAESKW.
 */
abstract class ECDHESAESKW implements KeyAgreementWrappingInterface
{
    /**
     * {@inheritdoc}
     */
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array $complete_header, array &$additional_header_values)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $sender_key, $receiver_key, $complete_header, $additional_header_values);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $complete_header)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $receiver_key, null, $complete_header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();
}
