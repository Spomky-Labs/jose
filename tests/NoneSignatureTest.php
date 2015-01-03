<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\Algorithm\Signature\None;

class NoneSignatureTest extends \PHPUnit_Framework_TestCase
{
    public function testNoneSignAndVerify()
    {
        $key  = new JWK();
        $key->setValue("kty", "none");

        $none = new None();
        $data = 'aaa';

        $signature = $none->sign($key, $data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($key, $data, $signature));
    }
}
