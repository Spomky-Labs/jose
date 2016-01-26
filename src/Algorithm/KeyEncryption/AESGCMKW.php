<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Crypto\Cipher;
use Jose\Object\JWKInterface;

/**
 * Class AESGCMKW.
 */
abstract class AESGCMKW implements KeyEncryptionInterface
{
    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $cek
     * @param array                     $header
     *
     * @return mixed
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);

        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setAAD(null);
        $iv = openssl_random_pseudo_bytes(96 / 8);
        $encryted_cek = $cipher->encrypt($cek, Base64Url::decode($key->get('k')), $iv);

        $header['iv'] = Base64Url::encode($iv);
        $header['tag'] = Base64Url::encode($cipher->getTag());

        return $encryted_cek;
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $encryted_cek
     * @param array                     $header
     *
     * @return mixed
     */
    public function decryptKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($header);

        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setTag(Base64Url::decode($header['tag']));
        $cipher->setAAD(null);

        $cek = $cipher->decrypt($encryted_cek, Base64Url::decode($key->get('k')), Base64Url::decode($header['iv']));

        return $cek;
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->get('kty') || !$key->has('k')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    /**
     * @param array $header
     */
    protected function checkAdditionalParameters(array $header)
    {
        if (!array_key_exists('iv', $header) || !array_key_exists('tag', $header)) {
            throw new \InvalidArgumentException("Missing parameters 'iv' or 'tag'.");
        }
    }

    /**
     * @return int
     */
    abstract protected function getKeySize();
}
