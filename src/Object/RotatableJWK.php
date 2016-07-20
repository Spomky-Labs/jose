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
use Base64Url\Base64Url;
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
     * @var int
     */
    private $first_ttl;

    /**
     * @var int|null
     */
    private $expires_at = 0;

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
     * @param int    $first_ttl
     */
    public function __construct($filename, array $parameters, $ttl = 0, $first_ttl = 0)
    {
        Assertion::directory(dirname($filename), 'The selected directory does not exist.');
        Assertion::writeable(dirname($filename), 'The selected directory is not writable.');
        Assertion::integer($ttl, 'The parameter must an integer');
        Assertion::greaterOrEqualThan($ttl, 0, 'The parameter must be at least 0');
        Assertion::integer($first_ttl, 'The parameter must an integer');
        Assertion::greaterOrEqualThan($first_ttl, 0, 'The parameter must be at least 0');
        $this->filename = $filename;
        $this->parameters = $parameters;
        $this->ttl = $ttl;
        $this->first_ttl = $first_ttl;
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    private function getJWK()
    {
        if (null === $this->jwk) {
            $this->loadJWK();
        }
        if (0 !== $this->expires_at && $this->expires_at < time()) {
            $this->createJWK();
        }

        return $this->jwk;
    }

    private function loadJWK()
    {
        if (file_exists($this->filename)) {
            $content = file_get_contents($this->filename);
            if (false === $content) {
                $this->createJWK();
            }
            $content = json_decode($content, true);
            if (!is_array($content) || !array_key_exists('expires_at', $content) || !array_key_exists('jwk', $content)) {
                $this->createJWK();
            }
            if (0 !== $content['expires_at'] && $content['expires_at'] <= time()) {
                $this->createJWK();
            }
            $this->jwk = new JWK($content['jwk']);
        } else {
            $this->createJWK();
        }
    }

    private function createJWK()
    {
        $data = JWKFactory::createKey($this->parameters)->getAll();
        $data['kid'] = Base64Url::encode(random_bytes(64));
        $this->jwk = JWKFactory::createFromValues($data);

        if (0 !== $this->ttl) {
            if (!file_exists($this->filename) && 0 !== $this->first_ttl) {
                $this->expires_at = time() + $this->first_ttl;
            } else {
                $this->expires_at = time() + $this->ttl;
            }
        }
        file_put_contents(
            $this->filename,
            json_encode([
                'expires_at' => $this->expires_at,
                'jwk' => $this->jwk,
            ])
        );
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
