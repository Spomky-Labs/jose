<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A128KW as Wrapper;
use SpomkyLabs\Jose\Util\Base64Url;

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
            var_dump(strlen(Base64Url::decode($key->getValue("k"))));
            var_dump(Base64Url::decode($key->getValue("k")));
            throw new \InvalidArgumentException("The key size is not valid");
        }
    }

    public function getAlgorithmName()
    {
        return "A128KW";
    }
}
