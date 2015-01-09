<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWT;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\Dir;

class DirAlgorithmTest extends TestCase
{
    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $header = array();
        $key  = new JWK();
        $key->setValue("kty", "EC");

        $dir = new Dir();

        $header = array();

        $dir->getCEK($key, $header);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The key does not have 'dir' parameter or parameter returned an invalid value
     */
    public function testKeyParameterIsMissing()
    {
        $header = array();
        $key  = new JWK();
        $key->setValue("kty", "dir");

        $dir = new Dir();

        $header = array();

        $dir->getCEK($key, $header);
    }

    public function testValidCEK()
    {
        $header = array();
        $key  = new JWK();
        $key->setValue("kty", "dir")
            ->setValue("dir", "ABCD");

        $dir = new Dir();

        $header = array();

        $this->assertEquals("ABCD", $dir->getCEK($key, $header));
    }
}
