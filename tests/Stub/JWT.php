<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWTInterface;

/**
 * Class representing a JSON Web Token.
 */
class JWT implements JWTInterface
{
    private $header;
    private $payload = null;

    public function getHeader()
    {
        return $this->header;
    }

    public function getHeaderValue($key)
    {
        return isset($this->header[$key]) ? $this->header[$key] : null;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setHeader(array $header)
    {
        $this->header = $header;

        return $this;
    }

    public function setPayload($payload)
    {
        $this->payload = $payload;

        return $this;
    }
}
