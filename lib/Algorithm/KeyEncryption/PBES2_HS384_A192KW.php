<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

class PBES2_HS384_A192KW extends PBES2_AESKW
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
