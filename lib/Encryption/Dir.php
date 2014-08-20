<?php

namespace SpomkyLabs\JOSE\Encryption;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;

/**
 */
abstract class Dir implements JWKInterface, JWKEncryptInterface, JWKDecryptInterface
{
    public function toPrivate()
    {
        $values = $this->getValues()+array(
            'kty' => 'dir',
        );

        return $values;
    }

    public function toPublic()
    {
        return $this->toPrivate();
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data)
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data)
    {
        return $this->getValue('dir');
    }

    public function isPrivate()
    {
        return true;
    }
}
