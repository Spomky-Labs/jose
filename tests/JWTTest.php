<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Tests\Stub\JWT;
use SpomkyLabs\JOSE\Tests\Algorithm\EC;
use SpomkyLabs\JOSE\Tests\Algorithm\RSA;
use SpomkyLabs\JOSE\Tests\Algorithm\Dir;
use SpomkyLabs\JOSE\Tests\Stub\JWTManager;
use SpomkyLabs\JOSE\Tests\Stub\JWKManager;

class JWTTest extends \PHPUnit_Framework_TestCase
{
    public function testLoadJWSWithNoneAlgorithm()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);
        $header = array();
        $result = $jwt_manager->load('eyJqd2siOnsia3R5Ijoibm9uZSJ9fQ.eyJNeURhdGEiOiJJc1ZlcnlJbXBvcnRhbnQifQ.', $header);

        $this->assertEquals(array(
            'MyData' => 'IsVeryImportant',
            ),
            $result);

        $this->assertEquals(array(array('protected' => array(
            'jwk' => array(
                'kty' => 'none',
            ), ))),
            $header);
    }

    public function testLoadJWSWithPS512Algorithm()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);
        $header = array();

        $result = $jwt_manager->load('eyJraWQiOjEyMzQ1Njc4OSwiYWxnIjoiUFM1MTIifQ.eyJNeURhdGEiOiJJc1ZlcnlJbXBvcnRhbnQifQ.hB1IAB1IbZFyha0EMt999A6LxGhoDfMHfcwYalZk_dSQtVvzDkZnU3ZOMU-xQB6OjaRbQXNKTqTPuZk9sPySwWw9QTxb9EDgLWUvSB-Ug2zocLoznUtkLGE2dzRD6AeHMGyS4_YCmutPa5hkzaeXoJT8W6ZRvnb7Usbs6mMbPLhKhAPV_250r78jCkra5YCIcgg065qjuD0KVDQcHv7130N-wcVZm3e4RAIpGtpSImdzCZx3MwkR1kEoqelSavrb96AJaNbMNhJx8s_G1UpT61kMM_6jmY9r8bSy2Zi34rTk6nqt39xw3-FNeYwb9VO_36JV75sklu8iRQwVBlSFjg', $header);

        $this->assertEquals(array(
            'MyData' => 'IsVeryImportant',
            ),
            $result);

        $this->assertEquals(array(array('protected' => array(
            'kid' => 123456789,
            'alg' => 'PS512',
            ))),
            $header);
    }

    public function testGetCompactSerializedJson()
    {
        $jwk = new EC();
        $jwk->setValue('crv', 'P-521')
            ->setValue('x', "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
            ->setValue('y', "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
            ->setValue('d', "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $input = array(
            'iss' => 'spomky-labs',
            'MyData' => 'IsVeryImportant',
        );

        $jwt_manager = new JWTManager();
        $jwk_manager = new JWKManager();
        $jwt_manager->setKeyManager($jwk_manager);

        $jws = $jwt_manager->signAndConvert(
            true, //Compact
            $input, //The input
            array(array(
                'key' => $jwk,
                'protected' => array(
                    'alg' => 'ES512',
                    'jwk' => $jwk->toPublic(),
                    'jty' => 'JWT',
                ),
                'header' => array(
                    'not' => 'important',
                ),
            ))
        );

        $header = array();
        $result = $jwt_manager->load($jws, $header);

        $this->assertEquals(array(
            'iss' => 'spomky-labs',
            'MyData' => 'IsVeryImportant',
            ),
            $result);

        $this->assertEquals(array(array('protected' => array(
                'alg' => 'ES512',
                'jwk' => $jwk->toPublic(),
                'jty' => 'JWT',
            ))),
            $header);
    }

    public function testGetSerializedJson()
    {
        $jwk = new EC();
        $jwk->setValue('crv', 'P-521')
            ->setValue('x', "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
            ->setValue('y', "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
            ->setValue('d', "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $input = array(
            'iss' => 'spomky-labs',
            'MyData' => 'IsVeryImportant',
        );

        $jwt_manager = new JWTManager();
        $jwk_manager = new JWKManager();
        $jwt_manager->setKeyManager($jwk_manager);

        $jws = $jwt_manager->signAndConvert(
            false, //Not compact
            $input, //The input
            array(array(
                'key' => $jwk,
                'protected' => array(
                    'alg' => 'ES512',
                    'jwk' => $jwk->toPublic(),
                    'jty' => 'JWT',
                ),
                'header' => array(
                    'not' => 'important',
                ),
            ))
        );

        $header = array();
        $result = $jwt_manager->load($jws, $header);

        $this->assertEquals(array(
            'iss' => 'spomky-labs',
            'MyData' => 'IsVeryImportant',
            ),
            $result);

        $this->assertEquals(array(array(
            'protected' => array(
                'alg' => 'ES512',
                'jwk' => $jwk->toPublic(),
                'jty' => 'JWT',
            ),
            'header' => array(
                'not' => 'important',
            ), )),
            $header);
    }

    public function testLoadJWEFromIETFDraft()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        //This JWE is an example taken from the JWE Draft 31
        $header = array();
        $result = $jwt_manager->load('eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw', $header);

        $this->assertEquals("Live long and prosper.", $result);
        $this->assertEquals(array(
            'protected' => array('alg' => 'RSA1_5', 'enc' => 'A128CBC-HS256'),
        ), $header);
    }

    public function testCreateEncryptedJWK()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $jwk = new RSA();
        $jwk->setValues(array(
            "kty" => "RSA",
            "n"   => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e"   => "AQAB",
            "d"   => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        ));

        $jwe = $jwt_manager->encryptAndConvert(
            true,
            $jwk,
            array(array(
                'key' => $jwk,
            )),
            array(
                'typ' => 'JOSE',
                'jty' => 'JWT',
                "alg" => "RSA-OAEP-256",
                "enc" => "A256CBC-HS512",
            )
        );

        $headers = array();
        $result = $jwt_manager->load($jwe, $headers);
        $this->assertInstanceOf('SpomkyLabs\JOSE\JWKInterface', $result);
        $this->assertEquals($jwk, $result);
        $this->assertEquals(array(
            'protected' => array(
                'typ' => 'JOSE',
                'jty' => 'JWT',
                "alg" => "RSA-OAEP-256",
                "enc" => "A256CBC-HS512",
                "cty" => "jwk+json",
            ),
        ), $headers);
    }

    public function testCreateEncryptedJWKSet()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $key_set = $jwk_manager->createJWKSet();

        $jwk = new RSA();
        $jwk->setValues(array(
            "kty" => "RSA",
            "n"   => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e"   => "AQAB",
            "d"   => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        ));

        $key_set->addKey($jwk);

        $jwe = $jwt_manager->encryptAndConvert(
            true,
            $key_set,
            array(array(
                'key' => $jwk,
            )),
            array(
                'typ' => 'JOSE',
                'jty' => 'JWT',
                "alg" => "RSA-OAEP-256",
                "enc" => "A256CBC-HS512",
            )
        );

        $headers = array();
        $result = $jwt_manager->load($jwe, $headers);
        $this->assertInstanceOf('SpomkyLabs\JOSE\JWKSetInterface', $result);
        $this->assertEquals($key_set, $result);
        $this->assertEquals(array(
            'protected' => array(
                'typ' => 'JOSE',
                'jty' => 'JWT',
                "alg" => "RSA-OAEP-256",
                "enc" => "A256CBC-HS512",
                "cty" => "jwkset+json",
            ),
        ), $headers);
    }

    public function testCreateEncryptedWithECDH_ES()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $recipient_jwk = new EC();
        $recipient_jwk->setValues(array(
            "kty" => "EC",
            "crv" => "P-256",
            "x"   => "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y"   => "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        ));

        $sender_jwk = new EC();
        $sender_jwk->setValues(array(
            "kty" => "EC",
            "crv" => "P-256",
            "x"   => "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y"   => "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d"   => "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        ));

        $jwe = $jwt_manager->encryptAndConvert(
            true,
            "The true sign of intelligence is not knowledge but imagination.",
            array(array(
                'key' => $recipient_jwk,
            )),
            array(
                "alg" => "ECDH-ES",
                "enc" => "A256CBC-HS512",
                "apu" => "QWxpY2U",
                "apv" => "Qm9i",
            ),
            array(),
            $sender_jwk);

        $result = $jwt_manager->load($jwe);

        $this->assertEquals('The true sign of intelligence is not knowledge but imagination.', $result);
    }

    public function testCreateEncryptedPlainText()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $jwk = new Dir();
        $jwk->setValues(array(
            "dir" => 'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q',

        ));

        $jwe = $jwt_manager->encryptAndConvert(
            true, //Compact
            "The true sign of intelligence is not knowledge but imagination.", // Input
            array(array(
                'key' => $jwk,
            )),
            array(
                "enc" => "A256CBC-HS512",
                'typ' => 'JOSE',
                "alg" => "dir",
            )
        );

        $headers = array();
        $result = $jwt_manager->load($jwe, $headers);

        $this->assertEquals('The true sign of intelligence is not knowledge but imagination.', $result);
        $this->assertEquals(array("protected" => array(
            "enc" => "A256CBC-HS512",
            'typ' => 'JOSE',
            "alg" => "dir",
        )), $headers);
    }

    public function testCreateEncryptedPlainTextUsingDeflate()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        $jwk = new Dir();
        $jwk->setValues(array(
            "dir" => 'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q',

        ));

        $jwe = $jwt_manager->encryptAndConvert(
            true, //Compact
            "The true sign of intelligence is not knowledge but imagination.", // Input
            array(array(
                'key' => $jwk,
            )),
            array(
                "enc" => "A256CBC-HS512",
                'typ' => 'JOSE',
                "alg" => "dir",
                'zip' => 'DEF',
            )
        );

        $headers = array();
        $result = $jwt_manager->load($jwe, $headers);

        $this->assertEquals('The true sign of intelligence is not knowledge but imagination.', $result);
        $this->assertEquals(array("protected" => array(
            "enc" => "A256CBC-HS512",
            'typ' => 'JOSE',
            "alg" => "dir",
            'zip' => 'DEF',
        )), $headers);
    }

    public function testLoadJWSSerializedJson()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        //This JWS is an example taken from the JWS Draft 31
        $header = array();
        $result = $jwt_manager->load('{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"2010-12-29"},"signature":"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},{"protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}]}', $header);
        $this->assertEquals(array(
            'iss' => "joe",
            'exp' => 1300819380,
            'http://example.com/is_root' => true,
        ), $result);
        $this->assertEquals(array(
            array(
                'protected' => array(
                    'alg' => 'RS256',
                ), 'header' => array(
                    'kid' => '2010-12-29',
            ), ), array(
                'protected' => array(
                    'alg' => 'ES256',
                ), 'header' => array(
                    'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
            ), ),
        ), $header);
    }

    public function testLoadJWESerializedJson()
    {
        $jwk_manager = new JWKManager();
        $jwt_manager = new JWTManager();

        $jwt_manager->setKeyManager($jwk_manager);

        //This JWE is an example taken from the JWE Draft 31
        $headers = array();
        $result = $jwt_manager->load('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}', $headers);

        $this->assertEquals("Live long and prosper.", $result);
        $this->assertEquals(array(
            'protected' => array(
                'enc' => "A128CBC-HS256",
            ),
            'unprotected' => array(
                'jku' => "https://server.example.com/keys.jwks",
            ),
            "header" => array(
                'alg' => "RSA1_5",
                'kid' => "2011-04-29",
            ), ),
            $headers
        );
    }

    /*public function testLoadJWKFromUrl()
    {
        $jwk_manager = new JWKManager();

        $result = $jwk_manager->loadFromUrl('https://www.googleapis.com/oauth2/v2/certs');
        $this->assertInstanceOf('SpomkyLabs\JOSE\JWKSetInterface', $result);
    }*/
}
