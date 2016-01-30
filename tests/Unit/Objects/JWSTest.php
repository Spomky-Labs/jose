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
use Jose\Factory\JWSFactory;

/**
 * Class JWSTest.
 *
 * @group JWS
 * @group Unit
 */
class JWSTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testJWS()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = JWSFactory::createJWS($claims);

        $this->assertTrue($jws->hasClaims());
        $this->assertTrue($jws->hasClaim('nbf'));
        $this->assertTrue($jws->hasClaim('iss'));
        $this->assertEquals('Me', $jws->getClaim('iss'));
        $this->assertEquals($claims, json_decode(Base64Url::decode($jws->getEncodedPayload()), true));
        $this->assertEquals($claims, $jws->getPayload());
        $this->assertEquals($claims, $jws->getClaims());
        $this->assertEquals(0, $jws->countSignatures());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     */
    public function testToCompactJSONFailed()
    {
        $jws = JWSFactory::createJWS([
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ]);

        $jws->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     */
    public function testToFlattenedJSONFailed()
    {
        $jws = JWSFactory::createJWS([
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ]);

        $jws->toFlattenedJSON(0);
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage No signature.
     */
    public function testToJSONFailed()
    {
        $jws = JWSFactory::createJWS([
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ]);

        $jws->toJSON();
    }
}
