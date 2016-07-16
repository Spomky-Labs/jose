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
use Jose\Factory\JWKFactory;

/**
 * Class RotatableJWK.
 */
final class RotatableJWK implements JWKInterface
{
    /**
     * @var \Jose\Object\JWKInterface
     */
    private $jwk;

    /**
     * @var string
     */
    private $filename;

    /**
     * @var int
     */
    private $ttl;

    /**
     * @var array
     */
    private $parameters;

    /**
     * RotatableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $ttl
     */
    public function __construct($filename, array $parameters, $ttl = 0)
    {
        Assertion::directory(basename($filename), 'The selected directory does not exist.');
        $this->filename = $filename;
        $this->parameters = $parameters;
        $this->ttl = $ttl;
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    private function getJWK()
    {
        if (null === $this->jwk) {
            $this->createJWK();
        }

        return $this->jwk;
    }

    private function loadJWK()
    {
    }

    private function createJWK()
    {
        $jwk = JWKFactory::createKey($this->parameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getAll()
    {
        return $this->getJWK()->getAll();
    }

    /**
     * {@inheritdoc}
     */
    public function get($key)
    {
        return $this->getJWK()->get($key);
    }

    /**
     * {@inheritdoc}
     */
    public function has($key)
    {
        return $this->getJWK()->has($key);
    }

    /**
     * {@inheritdoc}
     */
    public function thumbprint($hash_algorithm)
    {
        return $this->getJWK()->thumbprint($hash_algorithm);
    }

    /**
     * {@inheritdoc}
     */
    public function toPublic()
    {
        return $this->getJWK()->toPublic();
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getJWK()->jsonSerialize();
    }
}
