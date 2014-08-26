<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\HMAC as Base;

/**
 */
class HMAC extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'oct');
    }
}
