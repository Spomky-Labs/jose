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

use Base64Url\Base64Url;

/**
 * Class SignatureInstruction.
 */
final class Signature implements SignatureInterface
{
    /**
     * @var null|string
     */
    private $encoded_protected_headers = null;

    /**
     * @var array
     */
    private $protected_headers = [];

    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var string
     */
    private $signature;

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeaders()
    {
        return $this->protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedProtectedHeaders()
    {
        return $this->encoded_protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedProtectedHeaders($encoded_protected_headers)
    {
        $signature = clone $this;
        $signature->encoded_protected_headers = $encoded_protected_headers;
        if (empty($encoded_protected_headers)) {
            $signature->protected_headers = [];
        } else {
            $signature->protected_headers = json_decode(Base64Url::decode($encoded_protected_headers), true);
        }

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function withProtectedHeaders(array $protected_headers)
    {
        $signature = clone $this;
        $signature->protected_headers = $protected_headers;
        $signature->encoded_protected_headers = Base64Url::encode(json_encode($signature->protected_headers));

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function withProtectedHeader($key, $value)
    {
        $signature = clone $this;
        $signature->protected_headers[$key] = $value;
        $signature->encoded_protected_headers = Base64Url::encode(json_encode($signature->protected_headers));

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeader($key)
    {
        if ($this->hasProtectedHeader($key)) {
            return $this->protected_headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The protected header "%s" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasProtectedHeader($key)
    {
        return array_key_exists($key, $this->protected_headers);
    }

    /**
     * {@inheritdoc}
     */
    public function withHeaders(array $headers)
    {
        $signature = clone $this;
        $signature->headers = $headers;

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function withHeader($key, $value)
    {
        $signature = clone $this;
        $signature->headers[$key] = $value;

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader($key)
    {
        if ($this->hasHeader($key)) {
            return $this->headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasHeader($key)
    {
        return array_key_exists($key, $this->headers);
    }

    public function getAllHeaders()
    {
        return array_merge(
            $this->getProtectedHeaders(),
            $this->getHeaders()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * {@inheritdoc}
     */
    public function withSignature($values)
    {
        $signature = clone $this;
        $signature->signature = $values;

        return $signature;
    }
}
