<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\JWKInterface;
use Jose\Operation\KeyEncryptionInterface;

/**
 * Class AESKW.
 */
abstract class AESKW implements KeyEncryptionInterface
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
     * @param JWKInterface $key
     * @param string       $cek
     * @param array        $header
     *
     * @return mixed
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap(Base64Url::decode($key->getValue('k')), $cek);
    }

    /**
     * @param JWKInterface $key
     * @param string       $encryted_cek
     * @param array        $header
     *
     * @return mixed
     */
    public function decryptKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap(Base64Url::decode($key->getValue('k')), $encryted_cek);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->getKeyType() || null === $key->getValue('k')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    /**
     * @return mixed
     */
    abstract protected function getWrapper();
}
