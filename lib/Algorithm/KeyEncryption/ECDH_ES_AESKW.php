<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementWrappingInterface;
use Jose\Operation\AdditionalHeaderParametersInterface;

abstract class ECDH_ES_AESKW implements KeyAgreementWrappingInterface, AdditionalHeaderParametersInterface
{
    public function getAdditionalHeaderParameters(JWKInterface $sender_key, JWKInterface $receiver_key = null)
    {
        $ecdh_es = new ECDH_ES();

        return $ecdh_es->getAdditionalHeaderParameters($sender_key, $receiver_key);
    }

    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_algorithm, $encryption_key_length)
    {
        $agreement_key = $this->getAgreementKey($sender_key, $receiver_key, $encryption_algorithm, $encryption_key_length);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    public function unwrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $encrypted_cek, $encryption_algorithm, $encryption_key_length)
    {
        $agreement_key = $this->getAgreementKey($sender_key, $receiver_key, $encryption_algorithm, $encryption_key_length);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @param string  $encryption_algorithm
     * @param integer $encryption_key_length
     */
    private function getAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $encryption_algorithm, $encryption_key_length)
    {
        $ecdh_es = new ECDH_ES();

        return $ecdh_es->getAgreementKey($sender_key, $receiver_key, $encryption_algorithm, $encryption_key_length);
    }

    abstract protected function getWrapper();
}
