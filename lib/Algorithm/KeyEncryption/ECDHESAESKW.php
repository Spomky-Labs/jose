<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementWrappingInterface;

/**
 * Class ECDHESAESKW
 * @package SpomkyLabs\Jose\Algorithm\KeyEncryption
 */
abstract class ECDHESAESKW implements KeyAgreementWrappingInterface
{
    /**
     * @param  JWKInterface $sender_key
     * @param  JWKInterface $receiver_key
     * @param  string       $cek
     * @param  int          $encryption_key_length
     * @param  array        $header
     * @return mixed
     */
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array &$header)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->setAgreementKey($sender_key, $receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    /**
     * @param  JWKInterface $receiver_key
     * @param  string       $encrypted_cek
     * @param  int          $encryption_key_length
     * @param  array        $header
     * @return mixed
     */
    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $header)
    {
        $ecdh_es = new ECDHES();

        $agreement_key = $ecdh_es->getAgreementKey($receiver_key, $encryption_key_length, $header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @return mixed
     */
    abstract protected function getWrapper();
}
