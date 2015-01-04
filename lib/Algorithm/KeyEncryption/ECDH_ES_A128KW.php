<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

class ECDH_ES_A128KW extends ECDH_ES_AESKW
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
