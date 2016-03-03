<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

use Jose\Algorithm\ContentEncryptionAlgorithmInterface;

/**
 *
 */
abstract class AESCBCHS implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent($data, $cek, $iv, $aad, $encoded_protected_header, &$tag)
    {
        $k = substr($cek, strlen($cek) / 2);

        $cyphertext = openssl_encrypt($data, $this->getMode($k), $k, OPENSSL_RAW_DATA, $iv);

        $tag = $this->calculateAuthenticationTag($cyphertext, $cek, $iv, $aad, $encoded_protected_header);

        return $cyphertext;
    }

    /**
     * @param string      $data
     * @param string      $cek
     * @param string      $iv
     * @param string      $aad
     * @param string      $encoded_protected_header
     * @param string|null $aad
     * @param string      $tag
     *
     * @return string
     */
    public function decryptContent($data, $cek, $iv, $aad, $encoded_protected_header, $tag)
    {
        if (false === $this->checkAuthenticationTag($data, $cek, $iv, $aad, $encoded_protected_header, $tag)) {
            return;
        }

        $k = substr($cek, strlen($cek) / 2);

        return openssl_decrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * @param $encrypted_data
     * @param $cek
     * @param $iv
     * @param $aad
     * @param string $encoded_header
     *
     * @return string
     */
    protected function calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header)
    {
        $calculated_aad = $encoded_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }
        $mac_key = substr($cek, 0, strlen($cek) / 2);
        $auth_data_length = strlen($encoded_header);

        $secured_input = implode('', [
            $calculated_aad,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8), // str_pad(dechex($auth_data_length), 4, "0", STR_PAD_LEFT)
        ]);
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return  substr($hash, 0, strlen($hash) / 2);
    }

    /**
     * @param string      $authentication_tag
     * @param string      $encoded_header
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param string|null $aad
     *
     * @return bool
     */
    protected function checkAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header, $authentication_tag)
    {
        return $authentication_tag === $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header);
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();

    /**
     * @return int
     */
    public function getIVSize()
    {
        return 128;
    }

    /**
     * @param string $k
     *
     * @return string
     */
    private function getMode($k)
    {
        return 'aes-'.(8 *  strlen($k)).'-cbc';
    }
}
