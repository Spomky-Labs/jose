<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWT;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Jose\Algorithm\Signature\None;

class NoneSignatureTest extends TestCase
{
    public function testNoneSignAndVerifyAlgorithm()
    {
        $key  = new JWK();
        $key->setValue("kty", "none");

        $none = new None();
        $data = "Je suis Charlie";

        $signature = $none->sign($key, $data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($key, $data, $signature));
    }
    
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $key  = new JWK();
        $key->setValue("kty", "EC");

        $none = new None();
        $data = "Je suis Charlie";

        $none->sign($key, $data);
    }

    public function testNoneSignAndVerifyComplete()
    {
        $jwt = new JWT();
        $jwt->setProtectedHeader(array(
            "alg" => "none",
        ));
        $jwt->setPayload("Je suis Charlie");

        $jwk  = new JWK();
        $jwk->setValue("kty", "none");
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $jwt_manager = $this->loadJWTManager();

        $signed = $jwt_manager->sign($jwt, $jwk_set);
        $result = $jwt_manager->load($signed);

        $this->assertInstanceOf("Jose\JWSInterface", $result);
        $this->assertEquals("Je suis Charlie", $result->getPayload());
        $this->assertEquals("none", $result->getAlgorithm());
    }
}
