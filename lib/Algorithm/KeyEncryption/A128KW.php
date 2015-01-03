<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

/**
 */
class A128KW extends AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }
}
