<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Tests\Algorithm\JWK;
use SpomkyLabs\JOSE\Algorithm\EC as Base;

/**
 */
class EC extends Base
{
    use JWK;
    protected $values = array('kty'=>'EC');
}
