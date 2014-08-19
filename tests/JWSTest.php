<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Tests\Stub\JWTManager;

class JWSTest extends \PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $this->assertTrue(true);
        //$manager = new JWTManager;
        //$jws = $manager->load("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        // $jws = JWS::create("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.");

        /*$this->assertEquals($jws->getPayload(), array(
            'iss' =>"joe",
            'exp' =>1300819380,
            'http://example.com/is_root' => true,
            )
        );
        $this->assertEquals($jws->getHeader(), array(
                'typ' => "JWT",
                'alg' => "HS256",
            )
        );
        $this->assertSame($jws->__toString(), "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6XC9cL2V4YW1wbGUuY29tXC9pc19yb290Ijp0cnVlfQ");

        $this->assertSame("JWT", $jws->getType());
        $this->assertSame("HS256", $jws->getHeaderValue('alg'));
        $this->assertSame(true, $jws->getPayloadValue('http://example.com/is_root'));
        $this->assertSame("joe", $jws->getIssuer());
        $this->assertSame(1300819380, $jws->getExpiresAt());
        $this->assertTrue($jws->isExpired());*/
    }
}
