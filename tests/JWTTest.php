<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Base64Url;
use SpomkyLabs\JOSE\Tests\Stub\JWT;
use SpomkyLabs\JOSE\Tests\Signature\ECDSA;
use SpomkyLabs\JOSE\Tests\Stub\JWTManager;
use SpomkyLabs\JOSE\Tests\Stub\JWKManager;

class JWTTest extends \PHPUnit_Framework_TestCase
{
    public function testLoadJWSWithNoneAlgorithm()
    {
        $jwk_manager = new JWKManager;
        $jwt_manager = new JWTManager;

        $jwt_manager->setKeyManager($jwk_manager);
        $jwt = $jwt_manager->load('eyJqd2siOnsiYWxnIjoibm9uZSJ9LCJpc3MiOiJzcG9ta3ktbGFicyJ9.eyJNeURhdGEiOiJJc1ZlcnlJbXBvcnRhbnQifQ.');

        $this->assertInstanceOf('SpomkyLabs\JOSE\JWTInterface', $jwt);
        $this->assertEquals(array(
                'jwk'=>array('alg'=>'none'),
                'iss'=>'spomky-labs',
            ),
            $jwt->getheader());
    }
    public function testGetCompactSerializedJson()
    {
        $jwk = new ECDSA;
        $jwk->setCurve('P-521')
              ->setX("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
              ->setY("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
              ->setD("AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $jwt = new JWT;
        $jwt->setHeader(array(
            'jwk'=>$jwk->toPrivate(),
            'jty'=>'JWT',
            'iss'=>'spomky-labs',
        ));
        $jwt->setPayload(array(
            'MyData'=>'IsVeryImportant'
        ));

        $jwt_manager = new JWTManager;
        $jwk_manager = new JWKManager;
        $jwt_manager->setKeyManager($jwk_manager);

        $jws = $jwt_manager->convertToCompactSerializedJson($jwt,$jwk);

        $result = $jwt_manager->load($jws);

        $this->assertInstanceOf('SpomkyLabs\JOSE\JWTInterface', $result);
        $this->assertEquals(array(
                'jwk'=>$jwk->toPrivate(),
                'jty'=>'JWT',
                'iss'=>'spomky-labs',
            ),
            $result->getheader());
    }
}
