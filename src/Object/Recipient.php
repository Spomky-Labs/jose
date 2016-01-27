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

/**
 * Class EncryptionInstruction.
 */
final class Recipient implements RecipientInterface
{
    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var null|string
     */
    private $encrypted_key = null;

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

    /**
     * {@inheritdoc}
     */
    public function getEncryptedKey()
    {
        return $this->encrypted_key;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncryptedKey($encrypted_key)
    {
        $recipient = clone $this;
        $recipient->encrypted_key = $encrypted_key;

        return $recipient;
    }
}
