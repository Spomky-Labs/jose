<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A192KW as Wrapper;
use SpomkyLabs\Jose\Util\Base64Url;

/**
 */
class A192GCMKW extends AESGCMKW
{
    protected function getKeySize()
    {
        return 192;
    }

    public function getAlgorithmName()
    {
        return "A192KW";
    }
}
