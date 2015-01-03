<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

class ECDH_ES_A192KW extends ECDH_ES_AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }
}
