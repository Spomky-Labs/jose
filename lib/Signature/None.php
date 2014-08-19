<?php

namespace SpomkyLabs\JOSE\Signature;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext)
 */
abstract class None implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    public function toPrivate()
    {
        return array(
            'alg' => 'none',
        );
    }

    public function toPublic()
    {
        return $this->toPrivate();
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
}
