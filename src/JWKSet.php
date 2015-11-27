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

/**
 * Class JWKSet.
 */
final class JWKSet implements JWKSetInterface
{
    /**
     * @var int
     */
    private $position = 0;

    /**
     * @var array
     */
    protected $keys = [];

    /**
     * {@inheritdoc}
     */
    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($key)
    {
        if (isset($this->keys[$key])) {
            unset($this->keys[$key]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return ['keys' => array_values($this->getKeys())];
    }

    /**
     * {@inheritdoc}
     */
    public function count($mode = COUNT_NORMAL)
    {
        return count($this->getKeys(), $mode);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        $keys = $this->getKeys();

        return isset($keys[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        $keys = $this->getKeys();

        return isset($keys[$offset]) ? $keys[$offset] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $key)
    {
        $this->addKey($key);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        $this->removeKey($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function current()
    {
        return $this->offsetGet($this->position);
    }

    /**
     * {@inheritdoc}
     */
    public function key()
    {
        return $this->position;
    }

    /**
     * {@inheritdoc}
     */
    public function next()
    {
        $this->position++;
    }

    /**
     * {@inheritdoc}
     */
    public function rewind()
    {
        $this->position = 0;
    }

    /**
     * {@inheritdoc}
     */
    public function valid()
    {
        return $this->current() instanceof JWKInterface;
    }
}
