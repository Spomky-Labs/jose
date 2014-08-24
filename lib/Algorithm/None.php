<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext)
 */
abstract class None implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        return $this->getValues();
    }

    public function isPrivate()
    {
        return true;
    }

    public function isPublic()
    {
        return $this->isPrivate();
    }

    /**
     * @inheritdoc
     */
    public function sign($data, array $header = array())
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        return $signature === $this->sign($data);
    }

    public function getValue($key)
    {
        return null;
    }

    public function setValues(array $values)
    {
        return $this;
    }

    public function setValue($key, $value)
    {
        return $this;
    }
}
