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

use Base64Url\Base64Url;
use Jose\Object\JWKInterface;
use Jose\Util\StringUtil;

/**
 * Class PBES2AESKW.
 */
abstract class PBES2AESKW implements KeyWrappingInterface
{
    /**
     * @var int
     */
    private $salt_size;

    /**
     * @var int
     */
    private $nb_count;

    /**
     * @param int $salt_size
     * @param int $nb_count
     */
    public function __construct($salt_size = 64, $nb_count = 4096)
    {
        $this->salt_size = $salt_size;
        $this->nb_count = $nb_count;
    }

    /**
     * {@inheritdoc}
     */
    public function wrapKey(JWKInterface $key, $cek, array $complete_headers, array &$additional_headers)
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($complete_headers);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = StringUtil::generateRandomBytes($this->salt_size);
        $password = Base64Url::decode($key->get('k'));

        // We set headers parameters
        $additional_headers['p2s'] = Base64Url::encode($salt);
        $additional_headers['p2c'] = $this->nb_count;

        $derived_key = hash_pbkdf2($hash_algorithm, $password, $complete_headers['alg']."\x00".$salt, $this->nb_count, $key_size, true);

        return $wrapper->wrap($derived_key, $cek);
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapKey(JWKInterface $key, $encrypted_cek, array $header)
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($header);
        $this->checkHeaderAdditionalParameters($header);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = $header['alg']."\x00".Base64Url::decode($header['p2s']);
        $count = $header['p2c'];
        $password = Base64Url::decode($key->get('k'));

        $derived_key = hash_pbkdf2($hash_algorithm, $password, $salt, $count, $key_size, true);

        return $wrapper->unwrap($derived_key, $encrypted_cek);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
    {
        return self::MODE_WRAP;
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
    protected function checkHeaderAlgorithm(array $header)
    {
        if (!isset($header['alg']) || empty($header['alg'])) {
            throw new \InvalidArgumentException("The header parameter 'alg' is missing or invalid.");
        }
    }

    /**
     * @param array $header
     */
    protected function checkHeaderAdditionalParameters(array $header)
    {
        if (!array_key_exists('p2s', $header) || !array_key_exists('p2c', $header) || empty($header['p2s']) || empty($header['p2c'])) {
            throw new \InvalidArgumentException("The header is not valid. 'p2s' or 'p2c' parameter is missing or invalid.");
        }
    }

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();

    /**
     * @return int
     */
    abstract protected function getKeySize();
}
