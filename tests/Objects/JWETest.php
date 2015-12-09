<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\JWE;

/**
 * Class JWETest.
 */
class JWETest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testJWE()
    {
        $jwe = new JWE();
        $jwe = $jwe->withProtectedHeaders([
            'jty'  => 'JWT',
            'cty'  => 'JOSE+JSON',
            'crit' => ['alg', 'iss'],
            'zip'  => 'DEF',
        ]);
        $jwe = $jwe->withProtectedHeader('foo', 'www.example.com');
        $jwe = $jwe->withUnprotectedHeaders([
            'alg' => 'ES256',
            'enc' => 'A128CBC-HS256',
        ]);
        $jwe = $jwe->withUnprotectedHeader('bar', 'me@example.com');
        $jwe = $jwe->withClaims([
            'jti' => 'ABCD',
            'iss' => 'me.example.com',
            'aud' => 'you.example.com',
            'sub' => 'him.example.com',
            'exp' => 123456,
            'nbf' => 123000,
            'iat' => 123000,
        ]);

        $this->assertEquals('ABCD', $jwe->getClaim('jti'));
        $this->assertEquals('me.example.com', $jwe->getClaim('iss'));
        $this->assertEquals('you.example.com', $jwe->getClaim('aud'));
        $this->assertEquals('him.example.com', $jwe->getClaim('sub'));
        $this->assertEquals(123456, $jwe->getClaim('exp'));
        $this->assertEquals(123000, $jwe->getClaim('nbf'));
        $this->assertEquals(123000, $jwe->getClaim('iat'));
        $this->assertEquals('JOSE+JSON', $jwe->getProtectedHeader('cty'));
        $this->assertEquals('ES256', $jwe->getUnprotectedHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $jwe->getUnprotectedHeader('enc'));
        $this->assertEquals('JWT', $jwe->getProtectedHeader('jty'));
        $this->assertEquals('DEF', $jwe->getProtectedHeader('zip'));
        $this->assertFalse($jwe->hasHeaderOrClaim('jwk'));
        $this->assertFalse($jwe->hasHeaderOrClaim('jku'));
        $this->assertFalse($jwe->hasHeaderOrClaim('kid'));
        $this->assertFalse($jwe->hasHeaderOrClaim('x5u'));
        $this->assertEquals(['alg', 'iss'], $jwe->getProtectedHeader('crit'));
    }
}
