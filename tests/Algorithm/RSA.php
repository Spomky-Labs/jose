<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\RSA as Base;

/**
 */
class RSA extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'RSA');
    }
}
