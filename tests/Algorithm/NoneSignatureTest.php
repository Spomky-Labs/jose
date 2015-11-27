<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\Signature\None;
use Jose\JWK;
use Jose\JWT;
use Jose\SignatureInstruction;
use Jose\Test\TestCase;

/**
 * Class NoneSignatureTest.
 */
class NoneSignatureTest extends TestCase
{
    /**
     *
     */
    public function testNoneSignAndVerifyAlgorithm()
    {
        $key = new JWK([
            'kty' => 'none',
        ]);

        $none = new None();
        $data = 'Je suis Charlie';

        $signature = $none->sign($key, $data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($key, $data, $signature));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key is not valid
     */
    public function testInvalidKey()
    {
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Je suis Charlie';

        $none->sign($key, $data);
    }

    /**
     *
     */
    public function testNoneSignAndVerifyComplete()
    {
        $jwt = new JWT();
        $jwt = $jwt->withProtectedHeader([
            'alg' => 'none',
        ]);
        $jwt = $jwt->withPayload('Je suis Charlie');

        $jwk = new JWK([
            'kty' => 'none',
        ]);

        $instruction1 = new SignatureInstruction($jwk, ['alg' => 'none']);

        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $signed = $signer->sign($jwt, [$instruction1]);

        $this->assertTrue(is_string($signed));

        $result = $loader->load($signed);

        $this->assertInstanceOf('Jose\JWSInterface', $result);

        $this->assertEquals('Je suis Charlie', $result->getPayload());
        $this->assertEquals('none', $result->getAlgorithm());
    }
}
