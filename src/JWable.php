<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose;

/**
 * Class JWable.
 */
trait JWable
{
    /**
     * @var string
     */
    protected $encoded_protected_header = '';

    /**
     * @var string
     */
    protected $input = null;

    /**
     * @var string
     */
    protected $encoded_payload = '';

    /**
     * @var array
     */
    protected $protected_headers = [];

    /**
     * @var array
     */
    protected $unprotected_headers = [];

    /**
     * @var null
     */
    protected $payload = null;

    /**
     * @return string
     */
    public function getEncodedProtectedHeader()
    {
        return $this->encoded_protected_header;
    }

    /**
     * @return string|null
     */
    public function getInput()
    {
        return $this->input;
    }

    /**
     * @return string
     */
    public function getEncodedPayload()
    {
        return $this->encoded_payload;
    }

    /**
     * @return array
     */
    public function getProtectedHeader()
    {
        return $this->protected_headers;
    }

    /**
     * @return array
     */
    public function getUnprotectedHeader()
    {
        return $this->unprotected_headers;
    }

    /**
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param string $input
     *
     * @return self
     */
    public function setInput($input)
    {
        $this->input = $input;

        return $this;
    }

    /**
     * @param string $encoded_protected_header
     *
     * @return self
     */
    public function setEncodedProtectedHeader($encoded_protected_header)
    {
        $this->encoded_protected_header = $encoded_protected_header;

        return $this;
    }

    /**
     * @param string $encoded_payload
     *
     * @return self
     */
    public function setEncodedPayload($encoded_payload)
    {
        $this->encoded_payload = $encoded_payload;

        return $this;
    }

    /**
     * @param array $values
     *
     * @return self
     */
    public function setProtectedHeader(array $values)
    {
        $this->protected_headers = $values;

        return $this;
    }

    /**
     * @param array $values
     *
     * @return self
     */
    public function setUnprotectedHeader(array $values)
    {
        $this->unprotected_headers = $values;

        return $this;
    }

    /**
     * @param string          $key
     * @param string|string[] $value
     *
     * @return self
     */
    public function setProtectedHeaderValue($key, $value)
    {
        $this->protected_headers[$key] = $value;

        return $this;
    }

    /**
     * @param string          $key
     * @param string|string[] $value
     *
     * @return self
     */
    public function setUnprotectedHeaderValue($key, $value)
    {
        $this->unprotected_headers[$key] = $value;

        return $this;
    }

    /**
     * @param $payload
     *
     * @return self
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;

        return $this;
    }
}
