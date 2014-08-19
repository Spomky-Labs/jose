<?php

namespace SpomkyLabs\JOSE\Tests;

use Mdanter\Ecc\ModuleConfig;
use SpomkyLabs\JOSE\Tests\Signature\ECDSA;

class ECDSATest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ModuleConfig::useGmp();
        //ModuleConfig::useBcMath();
    }

    //The values of these tests come from the JWS draft
    public function testHS256Verify()
    {
        $ecdsa = new ECDSA;
        $ecdsa->setCurve('P-256')
              ->setX('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU')
              ->setY('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0');

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

        $this->assertTrue($ecdsa->verify($data, $signature));
    }

    public function testHS256SignVerify()
    {
        $ecdsa = new ECDSA;
        $ecdsa->setCurve('P-256')
              ->setX('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU')
              ->setY('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0')
              ->setD('jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI');

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = $ecdsa->sign($data);

        $this->assertTrue($ecdsa->verify($data, $signature));
    }

    /*public function testHS384Verify()
    {
        $ecdsa = new ECDSA;
        $ecdsa->setCurve('P-384')
              ->setX('')
              ->setY('');

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = '';

        $this->assertTrue($ecdsa->verify($data, $signature));
    }*/

    public function testHS521Verify()
    {
        $ecdsa = new ECDSA;
        $ecdsa->setCurve('P-521')
              ->setX('AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk')
              ->setY('ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2');
        
        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn';

        $this->assertTrue($ecdsa->verify($data, $signature));
    }

    public function testHS521SignVerify()
    {
        $ecdsa = new ECDSA;
        $ecdsa->setCurve('P-521')
              ->setX("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
              ->setY("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
              ->setD("AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = $ecdsa->sign($data);

        $this->assertTrue($ecdsa->verify($data, $signature));
    }
}
