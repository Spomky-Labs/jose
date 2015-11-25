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

use Base64Url\Base64Url;
use Jose\Finder\JWKSetFinderInterface;
use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWKSetManager as Base;
use Jose\JWKSetManagerInterface;
use Jose\Behaviour\HasJWKManager;

/**
 */
class JWKSetManager implements JWKSetManagerInterface
{
    use HasJWKManager;

    /**
     * @var \Jose\Finder\JWKSetFinderInterface[]
     */
    private $finders = [];

    /**
     * {@inheritdoc}
     */
    public function addJWKSetFinder(JWKSetFinderInterface $finder)
    {
        $this->finders[] = $finder;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function findJWKSet(array $header)
    {
        foreach( $this->finders as $finder) {
            $result = $finder->findJWKSet($header);
            if ($result instanceof JWKSetInterface) {
                return $result;
            } elseif ($result instanceof JWKInterface) {
                $keyset = $this->createJWKSet();
                $keyset->addKey($result);

                return $keyset;
            } elseif (is_array($result)) {
                return $this->createJWKSet($result);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function createJWKSet(array $values = [])
    {
        $key_set = new JWKSet();
        if (array_key_exists('keys', $values)) {
            foreach ($values['keys'] as $value) {
                $key = $this->getJWKManager()->createJWK($value);
                $key_set->addKey($key);
            }
        }

        return $key_set;
    }
}
