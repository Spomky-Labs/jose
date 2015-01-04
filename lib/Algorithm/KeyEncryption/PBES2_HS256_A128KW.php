<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

class PBES2_HS256_A128KW extends PBES2_AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm()
    {
        return "sha256";
    }

    protected function getKeySize()
    {
        return 128/8;
    }
}
