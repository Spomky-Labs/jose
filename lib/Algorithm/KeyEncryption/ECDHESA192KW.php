<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

class ECDHESA192KW extends ECDHESAESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    public function getAlgorithmName()
    {
        return "ECDH-ES+A192KW";
    }
}
