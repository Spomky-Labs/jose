<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\Dir as Base;

/**
 */
class Dir extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'dir');
    }
}
