<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

class PBES2_HS512_A256KW extends PBES2_AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm()
    {
        return "sha512";
    }

    protected function getKeySize()
    {
        return 256/8;
    }

    public function getAlgorithmName()
    {
        return "PBES2-HS512+A256KW";
    }
}
