<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\Signature\None;
use Jose\Factory\LoaderFactory;
use Jose\Factory\SignerFactory;
use Jose\Object\JWK;
use Jose\Object\SignatureInstruction;
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
        $jwk = new JWK([
            'kty' => 'none',
        ]);

        $instruction1 = new SignatureInstruction($jwk, ['alg' => 'none']);

        $signer = SignerFactory::createSigner(['none'], $this->getPayloadConverters());
        $loader = LoaderFactory::createLoader($this->getPayloadConverters());

        $signed = $signer->sign('Je suis Charlie', [$instruction1], \Jose\JSONSerializationModes::JSON_COMPACT_SERIALIZATION);

        $this->assertTrue(is_string($signed));

        $result = $loader->load($signed);

        $this->assertInstanceOf('Jose\Object\JWSInterface', $result);

        $this->assertEquals('Je suis Charlie', $result->getPayload());
        $this->assertEquals('none', $result->getHeader('alg'));
    }
}
