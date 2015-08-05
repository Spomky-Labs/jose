<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use Base64Url\Base64Url;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\Dir;

/**
 * Class DirAlgorithmTest.
 */
class DirAlgorithmTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $header = array();
        $key  = new JWK();
        $key->setValue('kty', 'EC');

        $dir = new Dir();

        $dir->getCEK($key, $header);
    }

    /**
     *
     */
    public function testValidCEK()
    {
        $header = array();
        $key  = new JWK();
        $key->setValue('kty', 'dir')
            ->setValue('dir', Base64Url::encode('ABCD'));

        $dir = new Dir();

        $this->assertEquals('ABCD', $dir->getCEK($key, $header));
    }
}
