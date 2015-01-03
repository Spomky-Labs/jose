<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

/**
 */
class A256KW extends AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }
}
