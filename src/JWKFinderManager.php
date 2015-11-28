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
    public function findJWK(array $header)
    {
        $keys = ['keys' => []];
        foreach ($this->finders as $finder) {
            $result = $finder->findJWK($header);
            if (is_array($result)) {
                if (array_key_exists('keys', $result)) {
                    $keys['keys'] = array_merge($result['keys'], $keys['keys']);
                } else {
                    $keys['keys'][] = $result;
                }
            }
        }
        return $keys;
    }
}
