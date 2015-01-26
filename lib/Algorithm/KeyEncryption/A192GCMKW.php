<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

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
        return "A192GCMKW";
    }
}
