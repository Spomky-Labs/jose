<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

class ECDH_ES_A256KW extends ECDH_ES_AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }
}
