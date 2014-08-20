<?php

namespace SpomkyLabs\JOSE\Signature;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext)
 */
class None implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    use JWK;

    protected $values = array('alg' => 'none');

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

    /**
     * @inheritdoc
     */
    public function sign($data)
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature)
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
