<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Tests\Stub\JWT;
use SpomkyLabs\JOSE\Tests\Signature\ECDSA;
use SpomkyLabs\JOSE\Tests\Encryption\RSA;
use SpomkyLabs\JOSE\Tests\Stub\JWTManager;
use SpomkyLabs\JOSE\Tests\Stub\JWKManager;

class JWTTest extends \PHPUnit_Framework_TestCase
{
    public function testLoadJWSWithNoneAlgorithm()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

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
        $jwk = new ECDSA();
        $jwk->setCurve('P-521')
              ->setX("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
              ->setY("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
              ->setD("AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $jwt = new JWT();
        $jwt->setHeader(array(
            'jwk'=>$jwk->toPrivate(),
            'jty'=>'JWT',
            'iss'=>'spomky-labs',
        ));
        $jwt->setPayload(array(
            'MyData'=>'IsVeryImportant'
        ));

        $jwt_manager = new JWTManager();
        $jwk_manager = new JWKManager();
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

    public function testCreateEncryptedJWK()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $jwk = new RSA();
        $jwk->setValues(array(
            "alg" =>"RSA-OAEP-256",
            "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e"   =>"AQAB",
            "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        ));

        $jwt = new JWT();
        $jwt->setHeader(array(
            "alg"=>"RSA-OAEP-256",
            "enc"=>"A256CBC-HS512",
            'iss'=>'spomky-labs',
            'typ'=>'JOSE',
            'cty'=>'jwk+json',
        ));
        $jwt->setPayload($jwk->toPrivate());

        $jwe = $jwt_manager->convertToCompactSerializedJson($jwt,$jwk);

        $result = $jwt_manager->load($jwe);
        $this->assertInstanceOf('SpomkyLabs\JOSE\JWKInterface', $result);
    }

    public function testLoadJWEFromIETFDraft()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);
        $result = $jwt_manager->load('eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw');

        $this->assertEquals("Live long and prosper.", $result);
    }
}
