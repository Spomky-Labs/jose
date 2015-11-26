<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\JWS;

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
        $jws = new JWS();
        $jws->setProtectedHeader([
            'jty'  => 'JWT',
            'cty'  => 'JOSE+JSON',
            'crit' => ['alg', 'iss'],
        ]);
        $jws->setUnprotectedHeader([
            'alg' => 'ES256',
        ]);
        $jws->setPayload([
            'jti' => 'ABCD',
            'iss' => 'me.example.com',
            'aud' => 'you.example.com',
            'sub' => 'him.example.com',
            'exp' => 123456,
            'nbf' => 123000,
            'iat' => 123000,
        ]);

        $this->assertEquals('ABCD', $jws->getJWTID());
        $this->assertEquals('me.example.com', $jws->getIssuer());
        $this->assertEquals('you.example.com', $jws->getAudience());
        $this->assertEquals('him.example.com', $jws->getSubject());
        $this->assertEquals(123456, $jws->getExpirationTime());
        $this->assertEquals(123000, $jws->getNotBefore());
        $this->assertEquals(123000, $jws->getIssuedAt());
        $this->assertEquals('JOSE+JSON', $jws->getContentType());
        $this->assertEquals('ES256', $jws->getAlgorithm());
        $this->assertEquals('JWT', $jws->getType());
        $this->assertNull($jws->getKeyID());
        $this->assertNull($jws->getJWKUrl());
        $this->assertNull($jws->getJWK());
        $this->assertNull($jws->getX509Url());
        $this->assertNull($jws->getX509CertificateChain());
        $this->assertNull($jws->getX509CertificateSha1Thumbprint());
        $this->assertNull($jws->getX509CertificateSha256Thumbprint());
        $this->assertEquals(['alg', 'iss'], $jws->getCritical());
    }
}
