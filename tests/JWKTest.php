<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;

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
        $jwk = new JWK();
        $jwk->setValues([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $this->assertEquals('EC', $jwk->getKeyType());
        $this->assertEquals('ES256', $jwk->getAlgorithm());
        $this->assertEquals('sign', $jwk->getPublicKeyUse());
        $this->assertEquals('0123456789', $jwk->getKeyID());
        $this->assertEquals(['sign'], $jwk->getKeyOperations());
        $this->assertEquals('P-256', $jwk->getValue('crv'));
        $this->assertNull($jwk->getX509Url());
        $this->assertNull($jwk->getX509CertificateChain());
        $this->assertNull($jwk->getX509CertificateSha1Thumbprint());
        $this->assertNull($jwk->getX509CertificateSha256Thumbprint());
        $this->assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->getValue('x'));
        $this->assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->getValue('y'));
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"}', json_encode($jwk));
    }

    /**
     *
     */
    public function testKeySet()
    {
        $jwk1 = new JWK();
        $jwk1->setValues([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $jwk2 = new JWK();
        $jwk2->setValues([
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
        $jwkset[] = $jwk1;
        $jwkset->addKey($jwk2);

        $this->assertEquals('{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}', json_encode($jwkset));
        $this->assertEquals(2, count($jwkset));
        $this->assertEquals(2, $jwkset->count());

        foreach ($jwkset as $key) {
            $this->assertEquals('EC', $key->getKeyType());
        }
        $this->assertEquals(2, $jwkset->key());

        for ($i = 0; $i < count($jwkset);$i++) {
            $this->assertEquals('EC', $jwkset[$i]->getKeyType());
        }

        $this->assertNull($jwkset[2]);
        $this->assertEquals('9876543210', $jwkset[1]->getKeyID());
        unset($jwkset[1]);

        $this->assertEquals(1, count($jwkset));
        $this->assertEquals(1, $jwkset->count());

        $this->assertTrue(isset($jwkset[0]));
        $this->assertFalse(isset($jwkset[1]));
    }
}
