<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\Algorithm\Signature\None;

class NoneSignatureTest extends \PHPUnit_Framework_TestCase
{
    public function testNoneSignAndVerify()
    {
        $key  = new JWK();
        $key->setValue("kty", "none");

        $none = new None();
        $data = "Je suis Charlie";

        $signature = $none->sign($key, $data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($key, $data, $signature));
    }
}
