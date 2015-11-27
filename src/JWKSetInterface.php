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

interface JWKSetInterface extends \Countable, \ArrayAccess, \Iterator, \JsonSerializable
{
    /**
     * Returns all keys in the key set.
     *
     * @return \Jose\JWKInterface[] An array of keys stored in the key set
     */
    public function getKeys();

    /**
     * Add key in the key set.
     *
     * @param \Jose\JWKInterface A key to store in the key set
     */
    public function addKey(JWKInterface $key);

    /**
     * Remove key from the key set.
     *
     * @param int $key Key to remove from the key set
     */
    public function removeKey($key);
}
