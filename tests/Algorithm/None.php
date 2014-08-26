<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\None as Base;

/**
 */
class None extends Base
{
    use JWK;
    protected $values = array('kty'=>'none');
}
