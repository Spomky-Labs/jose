<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\tests;

use Base64Url\Base64Url;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\Dir;
use SpomkyLabs\Jose\JWK;

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
        $header = [];
        $key = new JWK();
        $key->setValue('kty', 'EC');

        $dir = new Dir();

        $dir->getCEK($key, $header);
    }

    /**
     *
     */
    public function testValidCEK()
    {
        $header = [];
        $key = new JWK();
        $key->setValue('kty', 'dir')
            ->setValue('dir', Base64Url::encode('ABCD'));

        $dir = new Dir();

        $this->assertEquals('ABCD', $dir->getCEK($key, $header));
    }
}
