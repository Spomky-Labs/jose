<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use SpomkyLabs\JOSE\JWK;
use Jose\Operation\KeyAgreementWrappingInterface;

abstract class ECDH_ES_AESKW implements KeyAgreementWrappingInterface
{
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array &$header)
    {
        $agreement_key = $this->getAgreementKey($sender_key, $receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        $header = array_merge($header, array(
            "epk" => array(
                "kty" => $sender_key->getKeyType(),
                "crv" => $sender_key->getValue("crv"),
                "x"   => $sender_key->getValue("x"),
                "y"   => $sender_key->getValue("y"),
            ),
        ));

        return $wrapper->wrap($agreement_key, $cek);
    }

    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $header)
    {
        $sender_key = new JWK();
        $sender_key->setValues($header["epk"]);
        $agreement_key = $this->getAgreementKey($sender_key, $receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @param integer $encryption_key_length
     */
    private function getAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $encryption_key_length, array &$header)
    {
        $ecdh_es = new ECDH_ES();

        return $ecdh_es->getAgreementKey($sender_key, $receiver_key, $encryption_key_length, $header);
    }

    abstract protected function getWrapper();
}
