<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\JWS;

/**
 * Class JWSTest.
 */
class JWSTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testJWS()
    {
        /*$jws = new JWS();
        $jws = $jws->withProtectedHeaders([
            'jty'  => 'JWT',
            'cty'  => 'JOSE+JSON',
            'crit' => ['alg', 'iss'],
        ]);
        $jws = $jws->withUnprotectedHeaders([
            'alg' => 'ES256',
        ]);
        $jws = $jws->withClaims([
            'jti' => 'ABCD',
            'iss' => 'me.example.com',
            'aud' => 'you.example.com',
            'sub' => 'him.example.com',
            'exp' => 123456,
            'nbf' => 123000,
            'iat' => 123000,
        ]);

        $this->assertEquals('ABCD', $jws->getClaim('jti'));
        $this->assertEquals('me.example.com', $jws->getClaim('iss'));
        $this->assertEquals('you.example.com', $jws->getClaim('aud'));
        $this->assertEquals('him.example.com', $jws->getClaim('sub'));
        $this->assertEquals(123456, $jws->getClaim('exp'));
        $this->assertEquals(123000, $jws->getClaim('nbf'));
        $this->assertEquals(123000, $jws->getClaim('iat'));
        $this->assertEquals('JOSE+JSON', $jws->getProtectedHeader('cty'));
        $this->assertEquals('ES256', $jws->getUnprotectedHeader('alg'));
        $this->assertEquals('JWT', $jws->getProtectedHeader('jty'));
        $this->assertFalse($jws->hasHeaderOrClaim('jwk'));
        $this->assertFalse($jws->hasHeaderOrClaim('jku'));
        $this->assertFalse($jws->hasHeaderOrClaim('kid'));
        $this->assertFalse($jws->hasHeaderOrClaim('x5u'));
        $this->assertEquals(['alg', 'iss'], $jws->getProtectedHeader('crit'));*/
    }
}
