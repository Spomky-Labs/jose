<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

class ECDHESA128KW extends ECDHESAESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    public function getAlgorithmName()
    {
        return "ECDH-ES+A128KW";
    }
}
