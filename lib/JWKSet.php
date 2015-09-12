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

use Jose\JWKInterface;
use Jose\JWKSet as Base;

/**
 * Class JWKSet.
 */
class JWKSet extends Base
{
    /**
     * @var array
     */
    protected $keys = [];

    /**
     * @return array
     */
    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * Set keys in the Key.
     *
     * @param \Jose\JWKInterface $key A JWKInterface objects
     *
     * @return self
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;

        return $this;
    }

    /**
     * @param string $key
     *
     * @return self
     */
    public function removeKey($key)
    {
        if (isset($this->keys[$key])) {
            unset($this->keys[$key]);
        }

        return $this;
    }
}
