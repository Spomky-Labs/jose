<?php

namespace SpomkyLabs\Jose\tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\Algorithm\Signature\HS256;
use SpomkyLabs\Jose\Algorithm\Signature\HS384;
use SpomkyLabs\Jose\Algorithm\Signature\HS512;

/**
 * Class HMACSignatureTest.
 */
class HMACSignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $key  = new JWK();
        $key->setValue('kty', 'EC');

        $hmac = new HS256();
        $data = 'Je suis Charlie';

        $hmac->sign($key, $data);
    }

    /**
     *
     */
    public function testHS256SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            'kty' => 'oct',
            'k'  => 'foo',
        ));
        $hmac = new HS256();
        $data = 'Je suis Charlie';

        $signature = $hmac->sign($key, $data);

        $this->assertEquals(hex2bin('326eb338c465d3587f3349df0b96ba813670376cab1dfe0fd4ce126ab50ae354'), $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     *
     */
    public function testHS384SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            'kty' => 'oct',
            'k'  => 'foo',
        ));
        $hmac = new HS384();
        $data = 'Je suis Charlie';

        $signature = $hmac->sign($key, $data);

        $this->assertEquals(hex2bin('7074ed8ec356ce7d61d99b86caabccc741def9f3d0881c822b775dfe91520fdcb037b1b7f8bcf425796ec209decb760e'), $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     *
     */
    public function testHS512SignAndVerify()
    {
        $key = new JWK();
        $key->setValues(array(
            'kty' => 'oct',
            'k'  => 'foo',
        ));
        $hmac = new HS512();
        $data = 'Je suis Charlie';

        $signature = $hmac->sign($key, $data);

        $this->assertEquals(hex2bin('13d07b012d7a31369a0c12eccaeb40e79e5e2d11183a00f977fce075722206f45cdd77096d7ed719626868701076654cf03565c25a3f6b9e698e466717c3b0ca'), $signature);
        $this->assertTrue($hmac->verify($key, $data, $signature));
    }
}
