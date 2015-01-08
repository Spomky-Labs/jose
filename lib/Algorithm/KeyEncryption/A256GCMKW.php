<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use AESKW\A256KW as Wrapper;
use SpomkyLabs\Jose\Util\Base64Url;

/**
 */
class A256GCMKW extends AESGCMKW
{
    protected function getKeySize()
    {
        return 256;
    }

    public function getAlgorithmName()
    {
        return "A256KW";
    }
}
