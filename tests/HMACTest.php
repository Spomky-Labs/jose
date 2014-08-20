<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Signature\Hmac;

class HMACTest extends \PHPUnit_Framework_TestCase
{
    public function testHS256SignAndVerify()
    {
        $hmac = new Hmac();
        $hmac->setValue('alg','HS256')
             ->setValue('k','foo');
        $data = 'aaa';

        $signature = $hmac->sign($data);

        $this->assertEquals($signature, '3f63dbf1ed896b83f86274d9dc4174d3644aa54a4e9df8c8cb4b8b353d11d49d');
        $this->assertTrue($hmac->verify($data, $signature));
    }

    public function testHS384SignAndVerify()
    {
        $hmac = new Hmac();
        $hmac->setValue('alg','HS384')
             ->setValue('k','foo');
        $data = 'aaa';

        $signature = $hmac->sign($data);

        $this->assertEquals($signature, '5ba09deea6649cd6085cec53ae9116145c1fb97d1eda3e7d8531f8915161e68fbdadc9df36da612e0e15f185df917185');
        $this->assertTrue($hmac->verify($data, $signature));
    }

    public function testHS512SignAndVerify()
    {
        $hmac = new Hmac();
        $hmac->setValue('alg','HS512')
             ->setValue('k','foo');
        $data = 'aaa';

        $signature = $hmac->sign($data);

        $this->assertEquals($signature, '1b2b2a457f06a03e81093ac8e6c272d69b67f40eef6c396f14e9da0313bfb7e043f0a56b54051570733180cebc64dc6750d91bee4352ab7631902578a41bd38e');
        $this->assertTrue($hmac->verify($data, $signature));
    }
}
