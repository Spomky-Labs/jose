<?php

namespace SpomkyLabs\Jose;

/**
 * Class JWable
 * @package SpomkyLabs\Jose
 */
trait JWable
{
    /**
     * @var array
     */
    protected $protected_headers = array();
    /**
     * @var array
     */
    protected $unprotected_headers = array();
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
     * @return null
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param  array $values
     * @return $this
     */
    public function setProtectedHeader(array $values)
    {
        $this->protected_headers = $values;

        return $this;
    }

    /**
     * @param  array $values
     * @return $this
     */
    public function setUnprotectedHeader(array $values)
    {
        $this->unprotected_headers = $values;

        return $this;
    }

    /**
     * @param string          $key
     * @param string|string[] $value
     */
    public function setProtectedHeaderValue($key, $value)
    {
        $this->protected_headers[$key] = $value;

        return $this;
    }

/**
 * @param string          $key
 * @param string|string[] $value
 */
public function setUnprotectedHeaderValue($key, $value)
{
    $this->unprotected_headers[$key] = $value;

    return $this;
}

    /**
     * @param $payload
     * @return $this
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;

        return $this;
    }
}
