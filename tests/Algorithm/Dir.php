<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Tests\Algorithm\JWK;
use SpomkyLabs\JOSE\Algorithm\Dir as Base;

/**
 */
class Dir extends Base
{
    use JWK;
    protected $values = array('kty'=>'dir');
}
