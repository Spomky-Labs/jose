<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A128KW as Wrapper;
use SpomkyLabs\Jose\Util\Base64Url;

/**
 */
class A128GCMKW extends AESGCMKW
{
    protected function getKeySize()
    {
        return 128;
    }

    public function getAlgorithmName()
    {
        return "A128KW";
    }
}
