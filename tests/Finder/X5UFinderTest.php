<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Finder\X5UFinder;

/**
 * @group Finder
 */
class X5UFinderTest extends \PHPUnit_Framework_TestCase
{
    public function testWithValidParameter1()
    {
        $finder = new X5UFinder();
        $result = $finder->findJWKSet([
            'x5u' => 'https://www.googleapis.com/oauth2/v1/certs',
        ]);

        $this->assertTrue(is_array($result));
        $this->assertArrayHasKey('keys', $result);
        $this->assertEquals(2, count($result['keys']));
        $this->assertArrayHasKey('kty', $result['keys'][0]);
        $this->assertArrayHasKey('kty', $result['keys'][1]);
        $this->assertArrayHasKey('e', $result['keys'][0]);
        $this->assertArrayHasKey('e', $result['keys'][1]);
        $this->assertArrayHasKey('n', $result['keys'][0]);
        $this->assertArrayHasKey('n', $result['keys'][1]);
        $this->assertArrayHasKey('x5t', $result['keys'][0]);
        $this->assertArrayHasKey('x5t', $result['keys'][1]);
        $this->assertArrayHasKey('x5t#256', $result['keys'][0]);
        $this->assertArrayHasKey('x5t#256', $result['keys'][1]);
        $this->assertEquals('RSA', $result['keys'][1]['kty']);
        $this->assertEquals('RSA', $result['keys'][1]['kty']);
        $this->assertEquals('AQAB', $result['keys'][1]['e']);
        $this->assertEquals('AQAB', $result['keys'][1]['e']);
    }
}
