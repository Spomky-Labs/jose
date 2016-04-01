<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Assert\Assertion;

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

    public function __construct(array $keys = [])
    {
        if (array_key_exists('keys', $keys)) {
            foreach ($keys['keys'] as $value) {
                $this->addKey(new JWK($value));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function hasKey($index)
    {
        return array_key_exists($index, $this->keys);
    }

    /**
     * {@inheritdoc}
     */
    public function getKey($index)
    {
        Assertion::keyExists($this->keys, $index, 'Undefined index.');

        return $this->keys[$index];
    }

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
    public function current()
    {
        return isset($this->keys[$this->position]) ? $this->keys[$this->position] : null;
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

    /**
     * {@inheritdoc}
     */
    public function countKeys()
    {
        return count($this->keys);
    }
    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        return $this->hasKey($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        return $this->getKey($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $value)
    {
        $this->addKey($value);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        $this->removeKey($offset);
    }
}
