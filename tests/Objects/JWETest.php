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
 *
 * @group JWE
 */
class JWETest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The protected header "foo" does not exist
     */
    public function testProtectedHeaderDoesNotExist()
    {
        $jwe = new JWE();
        $jwe->getProtectedHeader('foo');
    }

    /**
     *
     */
    public function testRemoveProtectedHeader()
    {
        $jwe = new JWE();
        $jwe = $jwe->withProtectedHeader('foo', 'bar');
        $this->assertTrue($jwe->hasProtectedHeader('foo'));
        $this->assertEquals('bar', $jwe->getProtectedHeader('foo'));
        $jwe = $jwe->withoutProtectedHeader('foo');
        $jwe = $jwe->withoutProtectedHeader('foo');
        $this->assertFalse($jwe->hasProtectedHeader('foo'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The unprotected header "foo" does not exist
     */
    public function testUnprotectedHeaderDoesNotExist()
    {
        $jwe = new JWE();
        $jwe->getUnprotectedHeader('foo');
    }

    /**
     *
     */
    public function testRemoveUnprotectedHeader()
    {
        $jwe = new JWE();
        $jwe = $jwe->withUnprotectedHeader('foo', 'bar');
        $this->assertTrue($jwe->hasUnprotectedHeader('foo'));
        $this->assertEquals('bar', $jwe->getUnprotectedHeader('foo'));
        $jwe = $jwe->withoutUnprotectedHeader('foo');
        $jwe = $jwe->withoutUnprotectedHeader('foo');
        $this->assertFalse($jwe->hasUnprotectedHeader('foo'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The protected or unprotected headers do not contain header "foo"
     */
    public function testHeaderDoesNotExist()
    {
        $jwe = new JWE();
        $jwe->getHeader('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header or claim do not contain value with key "foo"
     */
    public function testHeaderOrClaimDoesNotExist()
    {
        $jwe = new JWE();
        $jwe->getHeaderOrClaim('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The payload does not contain claim "foo"
     */
    public function testClaimDoesNotExist()
    {
        $jwe = new JWE();
        $jwe->getClaim('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The payload does not contain claims
     */
    public function testPayloadHasNoClaim()
    {
        $jwe = new JWE();
        $jwe->getClaims();
    }

    /**
     *
     */
    public function testHeaderOrClaimExists()
    {
        $jwe = new JWE();
        $jwe = $jwe->withProtectedHeader('foo', 'bar');
        $jwe = $jwe->withClaim('bas', 'baz');
        $this->assertEquals('bar', $jwe->getHeaderOrClaim('foo'));
        $this->assertEquals('baz', $jwe->getHeaderOrClaim('bas'));
        $this->assertEquals(['bas' => 'baz'], $jwe->getClaims());
        $jwe = $jwe->withoutClaim('bas');
        $jwe = $jwe->withoutClaim('bas');
        $this->assertFalse($jwe->hasClaim('bas'));
    }

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
