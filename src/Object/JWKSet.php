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
                $key = new JWK($value);
                $this->keys[] = $key;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKey($index)
    {
        if (!isset($this->keys[$index])) {
            throw new \InvalidArgumentException('Undefined index.');
        }

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
        $keyset = clone $this;
        $keyset->keys[] = $key;

        return $keyset;
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($key)
    {
        if (isset($this->keys[$key])) {
            $keyset = clone $this;
            unset($keyset->keys[$key]);

            return $keyset;
        }

        return $this;
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
}
