<?php

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
        if (!trait_exists("\AESKW\AESKW")) {
            throw new \RuntimeException("The library 'spomky-labs/aes-key-wrap' is required to use Key Wrap based algorithms");
        }
    }

    /**
     * @param JWKInterface $sender_key
     * @param JWKInterface $receiver_key
     * @param string       $cek
     * @param int          $encryption_key_length
     * @param array        $header
     *
     * @return mixed
     */
    public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array $complete_header, array &$additional_header_values)
    //public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array &$header, $content_encyption_algorithm)
    //public function wrapAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $cek, $encryption_key_length, array &$header)
    {
        $ecdh_es = new ECDHES();

        //$agreement_key = $ecdh_es->setAgreementKey($sender_key, $receiver_key, $encryption_key_length, $complete_header, $additional_header_values);
        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $sender_key, $receiver_key, $complete_header, $additional_header_values);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap($agreement_key, $cek);
    }

    /**
     * @param JWKInterface $receiver_key
     * @param string       $encrypted_cek
     * @param int          $encryption_key_length
     * @param array        $header
     *
     * @return mixed
     */
    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $complete_header)
    //public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $header, $content_encyption_algorithm)
    //public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $header)
    {
        $ecdh_es = new ECDHES();

        //$agreement_key = $ecdh_es->getAgreementKey($receiver_key, $encryption_key_length, $complete_header);
        $agreement_key = $ecdh_es->getAgreementKey($encryption_key_length, $receiver_key, null, $complete_header);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * @return mixed
     */
    abstract protected function getWrapper();
}
