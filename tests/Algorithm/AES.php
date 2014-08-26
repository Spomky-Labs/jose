<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\AES as Base;

/**
 */
class AES extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'AES');
    }
}
