<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;

/**
 */
abstract class Dir implements JWKInterface, JWKEncryptInterface, JWKDecryptInterface
{
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
    public function encrypt($data, array &$header = array())
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data, array $header = array())
    {
        return $this->getValue('dir');
    }

    public function isPrivate()
    {
        return true;
    }

    public function isPublic()
    {
        return true;
    }
}
