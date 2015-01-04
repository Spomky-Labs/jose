<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A256KW as Wrapper;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 */
class A256KW extends AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function checkKey(JWKInterface $key)
    {
        parent::checkKey($key);
        if (32 !== strlen(Base64Url::decode($key->getValue("k")))) {
            throw new \InvalidArgumentException("The key size is not valid");
        }
    }
}
