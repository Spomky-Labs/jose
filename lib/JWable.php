<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
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
