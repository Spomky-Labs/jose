<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

class PBES2HS384A192KW extends PBES2AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm()
    {
        return "sha384";
    }

    protected function getKeySize()
    {
        return 192/8;
    }

    public function getAlgorithmName()
    {
        return "PBES2-HS384+A192KW";
    }
}
