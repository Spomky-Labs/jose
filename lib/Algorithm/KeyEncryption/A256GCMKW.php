<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;


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
