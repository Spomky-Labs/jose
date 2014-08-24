<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Tests\Algorithm\JWK;
use SpomkyLabs\JOSE\Algorithm\AES as Base;

/**
 */
class AES extends Base
{
    use JWK;
    protected $values = array('kty'=>'AES');
}
