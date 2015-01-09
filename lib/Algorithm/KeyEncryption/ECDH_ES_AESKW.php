<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementWrappingInterface;

abstract class ECDH_ES_AESKW implements KeyAgreementWrappingInterface
{
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array &$header)
    {
        $ecdh_es = new ECDH_ES();

        $agreement_key = $ecdh_es->setAgreementKey($sender_key, $receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $header)
    {
        $ecdh_es = new ECDH_ES();

        $agreement_key = $ecdh_es->getAgreementKey($receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    abstract protected function getWrapper();
}
