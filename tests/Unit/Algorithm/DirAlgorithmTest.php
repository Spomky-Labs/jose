<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\Algorithm\KeyEncryption\Dir;
use Jose\Object\JWK;
use Jose\Test\TestCase;

/**
 * Class DirAlgorithmTest.
 *
 * @group Unit
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
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $dir = new Dir();

        $dir->getCEK($key, $header);
    }

    /**
     *
     */
    public function testValidCEK()
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k'   => Base64Url::encode('ABCD'),
        ]);

        $dir = new Dir();

        $this->assertEquals('ABCD', $dir->getCEK($key, $header));
    }
}
