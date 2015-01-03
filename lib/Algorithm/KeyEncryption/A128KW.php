<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A128KW as Wrapper;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 */
class A128KW extends AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function checkKey(JWKInterface $key)
    {
        parent::checkKey($key);
        if (16 !== strlen(Base64Url::decode($key->getValue("k")))) {
            throw new \RuntimeException("The key size is not valid");
        }
    }
}
