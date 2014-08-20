<?php

namespace SpomkyLabs\JOSE\Encryption;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;

/**
 */
class Dir implements JWKInterface, JWKEncryptInterface, JWKDecryptInterface
{
    use JWK;

    protected $values = array('kty' => 'dir');

    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        return $this->getValues();
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
