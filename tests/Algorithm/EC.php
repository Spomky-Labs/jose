<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\EC as Base;

/**
 */
class EC extends Base
{
    use JWK;

    public function __construct()
    {
        $this->setValue('kty', 'EC');
    }
}
