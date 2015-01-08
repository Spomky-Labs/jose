<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;


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
