<?php

namespace SpomkyLabs\JOSE\Algorithm;

use Jose\JWK;
use Jose\JWKInterface;
use Jose\KeyOperation\SignatureInterface;
use Jose\KeyOperation\VerificationInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext)
 */
class None implements JWKInterface, SignatureInterface, VerificationInterface
{
    use JWK;

    protected $values = array('kty' => 'none');

    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
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
}
