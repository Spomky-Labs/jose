<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

class ECDHESA256KW extends ECDHESAESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    public function getAlgorithmName()
    {
        return "ECDH-ES+A256KW";
    }
}
