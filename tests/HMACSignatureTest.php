<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\Algorithm\Signature\HS256;
use SpomkyLabs\Jose\Algorithm\Signature\HS384;
use SpomkyLabs\Jose\Algorithm\Signature\HS512;

class HMACSignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $key  = new JWK();
        $key->setValue("kty", "EC");

        $hmac = new HS256();
        $data = "Je suis Charlie";

        $hmac->sign($key, $data);
    }

    public function testHS256SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => "foo",
        ));
        $hmac = new HS256();
        $data = "Je suis Charlie";

        $signature = $hmac->sign($key, $data);

        $this->assertEquals('d5a439ca3bf35184c55ab79d9941269b222162e183276b848090ade22eb45fbc', $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }

    public function testHS384SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => "foo",
        ));
        $hmac = new HS384();
        $data = "Je suis Charlie";

        $signature = $hmac->sign($key, $data);

        $this->assertEquals('ce386c732cff516dab38f42aae816ecbae340acda905eb5a924f3d53d73d4d31fdf685deae19496fc1e5f9e3a48756eb', $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }

    public function testHS512SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => "foo",
        ));
        $hmac = new HS512();
        $data = "Je suis Charlie";

        $signature = $hmac->sign($key, $data);

        $this->assertEquals('24138a039bd97ae80a8c034f58edee4905fb79426d2a06c561e029c482b2bbe16854692d130da5d01a42e28bbac27e36ee02d329d49f72f6083f3a7a7879a41f', $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }
}
