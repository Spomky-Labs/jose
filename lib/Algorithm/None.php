<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext)
 */
abstract class None implements JWKInterface, SignatureInterface, VerificationInterface
{
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
