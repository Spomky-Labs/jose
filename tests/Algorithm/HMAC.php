<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Tests\Algorithm\JWK;
use SpomkyLabs\JOSE\Algorithm\HMAC as Base;

/**
 */
class HMAC extends Base
{
    use JWK;
    protected $values = array('kty'=>'oct');
}
