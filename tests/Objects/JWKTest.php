<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\JWK;
use Jose\JWKSet;

/**
 * Class JWKTest.
 */
class JWKTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testKey()
    {
        $jwk = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
        ]);
        $jwk2 = $jwk->withValue('kid', '0123456789');

        $this->assertEquals('EC', $jwk->getKeyType());
        $this->assertEquals('ES256', $jwk->getAlgorithm());
        $this->assertEquals('sign', $jwk->getPublicKeyUse());
        $this->assertNull($jwk->getKeyID());
        $this->assertEquals('0123456789', $jwk2->getKeyID());
        $this->assertEquals(['sign'], $jwk->getKeyOperations());
        $this->assertEquals('P-256', $jwk->getValue('crv'));
        $this->assertNull($jwk->getX509Url());
        $this->assertNull($jwk->getX509CertificateChain());
        $this->assertNull($jwk->getX509CertificateSha1Thumbprint());
        $this->assertNull($jwk->getX509CertificateSha256Thumbprint());
        $this->assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->getValue('x'));
        $this->assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->getValue('y'));
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256"}', json_encode($jwk));
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"}', json_encode($jwk2));
        $this->assertNotSame($jwk, $jwk2);
    }

    /**
     *
     */
    public function testKeySet()
    {
        $jwk1 = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $jwkset = new JWKSet();
        $jwkset = $jwkset->addKey($jwk1);
        $jwkset = $jwkset->addKey($jwk2);

        $this->assertEquals('{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}', json_encode($jwkset));
        $this->assertEquals(2, count($jwkset));
        $this->assertEquals(2, $jwkset->count());

        foreach ($jwkset as $key) {
            $this->assertEquals('EC', $key->getKeyType());
        }
        $this->assertEquals(2, $jwkset->key());

        $this->assertEquals('9876543210', $jwkset->getKey(1)->getKeyID());
        $jwkset = $jwkset->removeKey(1);

        $this->assertEquals(1, count($jwkset));
        $this->assertEquals(1, $jwkset->count());

        $this->assertInstanceOf('\Jose\JWKInterface', $jwkset->getKey(0));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Undefined index.
     */
    public function testKeySet2()
    {
        $jwk1 = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $jwkset = new JWKSet();
        $jwkset = $jwkset->addKey($jwk1);
        $jwkset = $jwkset->addKey($jwk2);

        $jwkset->getKey(2);
    }
}
