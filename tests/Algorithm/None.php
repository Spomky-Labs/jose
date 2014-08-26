<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\None as Base;

/**
 */
class None extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'none');
    }
}
