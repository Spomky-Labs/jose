<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A192KW as Wrapper;
use Base64Url\Base64Url;

/**
 * Class A192KW.
 */
class A192KW extends AESKW
{
    /**
     * @return Wrapper
     */
    protected function getWrapper()
    {
        return new Wrapper();
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        parent::checkKey($key);
        if (24 !== strlen(Base64Url::decode($key->getValue("k")))) {
            throw new \InvalidArgumentException("The key size is not valid");
        }
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "A192KW";
    }
}
