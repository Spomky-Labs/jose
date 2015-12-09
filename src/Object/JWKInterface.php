<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWKInterface extends \JsonSerializable
{
    /**
     * Get all keys available in the JWK object.
     *
     * @return array Available keys of the JWK object
     */
    public function getKeys();

    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function getAll();

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed|null The value
     */
    public function get($key);

    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     *
     * @return bool
     */
    public function has($key);

    /**
     * Set values of the JWK object.
     *
     * @param string $key   Key
     * @param mixed  $value Value to store
     *
     * @return \Jose\Object\JWKInterface
     */
    public function withValue($key, $value);

    /**
     * Unset values of the JWK object.
     *
     * @param string $key Key
     *
     * @return \Jose\Object\JWKInterface
     */
    public function withoutValue($key);
}
