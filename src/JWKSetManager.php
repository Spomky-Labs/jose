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

use Jose\Behaviour\HasJWKManager;
use Jose\Finder\JWKSetFinderInterface;

/**
 */
final class JWKSetManager implements JWKSetManagerInterface
{
    use HasJWKManager;

    /**
     * JWKSetManager constructor.
     *
     * @param \Jose\JWKManagerInterface $jwk_manager
     */
    public function __construct(JWKManagerInterface $jwk_manager)
    {
        $this->setJWKManager($jwk_manager);
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
                $key_set = $key_set->addKey($key);
            }
        }

        return $key_set;
    }
}
