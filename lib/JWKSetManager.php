<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose;

use Jose\JWKSetManager as Base;
use SpomkyLabs\Jose\Behaviour\HasJWKManager;

/**
 */
class JWKSetManager extends Base
{
    use HasJWKManager;

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
