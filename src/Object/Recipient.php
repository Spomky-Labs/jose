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
     * @var \Jose\Object\JWKInterface
     */
    private $recipient_key;

    /**
     * @param array  $headers
     * @param string $encrypted_key
     *
     * @return \Jose\Object\Recipient
     */
    public static function createRecipientFromLoadedJWE(array $headers, $encrypted_key)
    {
        $recipient = new self();
        $recipient->headers = $headers;
        $recipient->encrypted_key = $encrypted_key;

        return $recipient;
    }

    /**
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $headers
     *
     * @return \Jose\Object\Recipient
     */
    public static function createRecipientForJWEEncryption(JWKInterface $recipient_key, array $headers = [])
    {
        $recipient = new self();
        $recipient->headers = $headers;
        $recipient->recipient_key = $recipient_key;

        return $recipient;
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
        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist.', $key));
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

    /**
     * {@inheritdoc}
     */
    public function getRecipientKey()
    {
        return $this->recipient_key;
    }

    /**
     * {@inheritdoc}
     */
    public function withRecipientKey(JWKInterface $recipient_key)
    {
        $recipient = clone $this;
        $recipient->recipient_key = $recipient_key;

        return $recipient;
    }
}
