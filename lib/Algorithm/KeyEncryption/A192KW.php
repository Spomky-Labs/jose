<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

/**
 */
class A192KW extends AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }
}
