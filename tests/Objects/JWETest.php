<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\JWE;

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
        $jwe->setProtectedHeader([
            'jty'  => 'JWT',
            'cty'  => 'JOSE+JSON',
            'crit' => ['alg', 'iss'],
            'zip'  => 'DEF',
        ]);
        $jwe->setProtectedHeaderValue('foo', 'www.example.com');
        $jwe->setUnprotectedHeader([
            'alg' => 'ES256',
            'enc' => 'A128CBC-HS256',
        ]);
        $jwe->setUnprotectedHeaderValue('bar', 'me@example.com');
        $jwe->setPayload([
            'jti' => 'ABCD',
            'iss' => 'me.example.com',
            'aud' => 'you.example.com',
            'sub' => 'him.example.com',
            'exp' => 123456,
            'nbf' => 123000,
            'iat' => 123000,
        ]);

        $this->assertEquals('ABCD', $jwe->getJWTID());
        $this->assertEquals('me.example.com', $jwe->getIssuer());
        $this->assertEquals('you.example.com', $jwe->getAudience());
        $this->assertEquals('him.example.com', $jwe->getSubject());
        $this->assertEquals(123456, $jwe->getExpirationTime());
        $this->assertEquals(123000, $jwe->getNotBefore());
        $this->assertEquals(123000, $jwe->getIssuedAt());
        $this->assertEquals('JOSE+JSON', $jwe->getContentType());
        $this->assertEquals('ES256', $jwe->getAlgorithm());
        $this->assertEquals('A128CBC-HS256', $jwe->getEncryptionAlgorithm());
        $this->assertEquals('JWT', $jwe->getType());
        $this->assertEquals('DEF', $jwe->getZip());
        $this->assertNull($jwe->getKeyID());
        $this->assertNull($jwe->getJWKUrl());
        $this->assertNull($jwe->getJWK());
        $this->assertNull($jwe->getX509Url());
        $this->assertNull($jwe->getX509CertificateChain());
        $this->assertNull($jwe->getX509CertificateSha1Thumbprint());
        $this->assertNull($jwe->getX509CertificateSha256Thumbprint());
        $this->assertEquals(['alg', 'iss'], $jwe->getCritical());
    }
}
