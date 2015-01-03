<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\Util\Base64Url;
use SpomkyLabs\JOSE\Algorithm\Signature\ES256;
//use SpomkyLabs\JOSE\Algorithm\Signature\ES384; //Not tested yet
use SpomkyLabs\JOSE\Algorithm\Signature\ES512;

class ECDSASignatureTest extends \PHPUnit_Framework_TestCase
{
    //The values of these tests come from the JWS draft
    public function testES256Verify()
    {
        $key = new JWK();
        $key->setValue('kty', 'EC')
            ->setValue('crv', 'P-256')
            ->setValue('x', 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU')
            ->setValue('y', 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0');

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

        $this->assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    public function testES256SignVerify()
    {
        $key = new JWK();
        $key->setValue('kty', 'EC')
            ->setValue('crv', 'P-256')
            ->setValue('x', 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU')
            ->setValue('y', 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0')
            ->setValue('d', 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI');

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $signature));
    }

    public function testHS512Verify()
    {
        $key = new JWK();
        $key->setValue('kty', 'EC')
            ->setValue('crv', 'P-521')
            ->setValue('x', 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk')
            ->setValue('y', 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2');

        $ecdsa = new ES512();

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn';

        $this->assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    public function testHS512SignVerify()
    {
        $key = new JWK();
        $key->setValue('kty', 'EC')
            ->setValue('crv', 'P-521')
            ->setValue('x', "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
            ->setValue('y', "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
            ->setValue('d', "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C");

        $ecdsa = new ES512();

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $signature));
    }
}
