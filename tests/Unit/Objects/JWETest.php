<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWEFactory;
use Jose\Object\Recipient;

/**
 * Class JWETest.
 *
 * @group JWE
 * @group Unit
 */
class JWETest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testJWE()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jwe = JWEFactory::createJWE($claims);

        $this->assertEquals(0, $jwe->countRecipients());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The recipient does not exist.
     */
    public function testToCompactJSONFailed()
    {
        $jwe = JWEFactory::createJWE([
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ]);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The shared protected header "plic" does not exist.
     */
    public function testAddAndGetSharedProtectedHeader()
    {
        $jwe = JWEFactory::createJWE([]);
        $jwe = $jwe->withSharedProtectedHeader('foo', 'bar');

        $this->assertEquals(['foo'=>'bar'], $jwe->getSharedProtectedHeaders());
        $this->assertEquals('bar', $jwe->getSharedProtectedHeader('foo'));
        $this->assertEquals('bar', $jwe->getSharedProtectedHeader('plic'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The shared header "plic" does not exist.
     */
    public function testAddSharedProtectedHeader()
    {
        $jwe = JWEFactory::createJWE([]);
        $jwe = $jwe->withSharedHeader('foo', 'bar');

        $this->assertEquals(['foo'=>'bar'], $jwe->getSharedHeaders());
        $this->assertEquals('bar', $jwe->getSharedHeader('foo'));
        $this->assertEquals('bar', $jwe->getSharedHeader('plic'));
    }
}
