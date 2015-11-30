<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Finder\JWKFinderInterface;

/**
 */
final class JWKFinderManager implements JWKFinderManagerInterface
{
    /**
     * @var \Jose\Finder\JWKFinderInterface[]
     */
    private $finders = [];

    /**
     * {@inheritdoc}
     */
    public function addJWKFinder(JWKFinderInterface $finder)
    {
        $this->finders[] = $finder;
    }

    /**
     * {@inheritdoc}
     */
    public function findJWK(array $header, $key_type)
    {
        $keys = ['keys' => []];
        foreach ($this->finders as $finder) {
            $result = $finder->findJWK($header);
            if (is_array($result)) {
                $this->addKey($keys, $result, $key_type);
            }
        }

        return $keys;
    }

    /**
     * @param array $keys
     * @param array $result
     * @param int   $key_type
     */
    private function addKey(array &$keys, array $result, $key_type)
    {
        if (array_key_exists('keys', $result)) {
            foreach ($result['keys'] as $key) {
                $this->addKey($keys, $key, $key_type);
            }
        } else {
            if (true === $this->isKeySearched($result, $key_type)) {
                $keys['keys'][] = $result;
            }
        }
    }

    /**
     * @param array $key
     * @param int   $key_type
     *
     * @return bool
     */
    private function isKeySearched(array $key, $key_type)
    {
        if ($key_type & self::KEY_TYPE_DIRECT && true === $this->isDirectKey($key)) {
            return true;
        }
        if ($key_type & self::KEY_TYPE_NONE && true === $this->isNoneKey($key)) {
            return true;
        }
        if ($key_type & self::KEY_TYPE_SYMMETRIC && true === $this->isSymmetricKey($key)) {
            return true;
        }
        if ($key_type & self::KEY_TYPE_PUBLIC && true === $this->isPublicKey($key)) {
            return true;
        }
        if ($key_type & self::KEY_TYPE_PRIVATE && true === $this->isPrivateKey($key)) {
            return true;
        }

        return false;
    }

    /**
     * @param array $key
     *
     * @return bool
     */
    private function isDirectKey(array $key)
    {
        return array_key_exists('kty', $key) && 'dir' === $key['kty'];
    }

    /**
     * @param array $key
     *
     * @return bool
     */
    private function isNoneKey(array $key)
    {
        return array_key_exists('kty', $key) && 'none' === $key['kty'];
    }

    /**
     * @param array $key
     *
     * @return bool
     */
    private function isSymmetricKey(array $key)
    {
        return array_key_exists('kty', $key) && 'oct' === $key['kty'];
    }

    /**
     * @param array $key
     *
     * @return bool
     */
    private function isPrivateKey(array $key)
    {
        if (!array_key_exists('kty', $key) || !in_array($key['kty'], ['RSA', 'EC'])) {
            return false;
        }

        return array_key_exists('d', $key);
    }

    /**
     * @param array $key
     *
     * @return bool
     */
    private function isPublicKey(array $key)
    {
        if (!array_key_exists('kty', $key) || !in_array($key['kty'], ['RSA', 'EC'])) {
            return false;
        }

        return !array_key_exists('d', $key);
    }
}
