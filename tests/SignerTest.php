<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test;

use Jose\JSONSerializationModes;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Jose\JWS;
use SpomkyLabs\Jose\SignatureInstruction;

/**
 * Class SignerTest.
 */
class SignerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No instruction.
     */
    public function testNoInstruction()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $signer->sign($input, []);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported input type.
     */
    public function testUnsupportedInputType()
    {
        $resource = fopen(__FILE__, 'r');
        $signer = $this->getSigner();
        $signer->sign($resource, []);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad instruction. Must implement SignatureInstructionInterface.
     */
    public function testBadInstruction()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $signer->sign($input, ['Bad instruction']);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No 'alg' parameter set in the header or the key.
     */
    public function testAlgParameterIsMissing()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction();
        $instruction->setKey($this->getKey1())
                    ->setProtectedHeader([]);

        $signer->sign($input, [$instruction]);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm 'foo' is not supported.
     */
    public function testAlgParameterIsNotSupported()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction();
        $instruction->setKey($this->getKey1())
                    ->setProtectedHeader(['alg' => 'foo']);

        $signer->sign($input, [$instruction]);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The serialization method 'foo_serialization' is not supported.
     */
    public function testSerializationIsNotSupported()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction();
        $instruction->setKey($this->getKey1())
                    ->setProtectedHeader(['alg' => 'HS512']);

        $signer->sign($input, [$instruction], 'foo_serialization');
    }

    /**
     *
     */
    public function testSignAndLoadCompact()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $input = $this->getKey3();

        $instruction1 = new SignatureInstruction();
        $instruction1->setKey($this->getKey1())
                     ->setProtectedHeader(['alg' => 'HS512']);

        $instruction2 = new SignatureInstruction();
        $instruction2->setKey($this->getKey2())
                     ->setProtectedHeader(['alg' => 'RS512']);

        $signatures = $signer->sign($input, [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);

        $this->assertTrue(is_string($signatures));

        /*
         * @var \Jose\JWSInterface[]
         */
        $loaded = $loader->load($signatures);

        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('\Jose\JWSInterface', $loaded[0]);
        $this->assertInstanceOf('\Jose\JWKInterface', $loaded[0]->getPayload());
        $this->assertEquals('HS512', $loaded[0]->getAlgorithm());

        $this->assertInstanceOf('\Jose\JWSInterface', $loaded[1]);
        $this->assertInstanceOf('\Jose\JWKInterface', $loaded[1]->getPayload());
        $this->assertEquals('RS512', $loaded[1]->getAlgorithm());
    }

    /**
     *
     */
    public function testSignAndLoadFlattened()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $instruction1 = new SignatureInstruction();
        $instruction1->setKey($this->getKey1())
                     ->setProtectedHeader(['alg'   => 'HS512'])
                     ->setUnprotectedHeader(['foo' => 'bar']);

        $signatures = $signer->sign(['baz', 'ban'], [$instruction1], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $this->assertTrue(is_string($signatures));

        /*
         * @var \Jose\JWSInterface
         */
        $loaded = $loader->load($signatures);

        $this->assertInstanceOf('\Jose\JWSInterface', $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getAlgorithm());
    }

    /**
     *
     */
    public function testSignAndLoad()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $instruction1 = new SignatureInstruction();
        $instruction1->setKey($this->getKey1())
                     ->setProtectedHeader(['alg'   => 'HS512'])
                     ->setUnprotectedHeader(['foo' => 'bar']);

        $instruction2 = new SignatureInstruction();
        $instruction2->setKey($this->getKey2())
                     ->setProtectedHeader(['alg' => 'RS512']);

        $signatures = $signer->sign('Je suis Charlie', [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);
        $this->assertTrue(is_string($signatures));

        $loaded = $loader->load($signatures);

        /*
         * @var \Jose\JWSInterface[] $loaded
         */
        $this->assertTrue(is_array($loaded));
        $this->assertEquals(2, count($loaded));
        foreach ($loaded as $jws) {
            $this->assertInstanceOf('\Jose\JWSInterface', $jws);
            $this->assertEquals('Je suis Charlie', $jws->getPayload());
            $this->assertTrue($loader->verifySignature($jws));
        }
        $this->assertEquals('HS512', $loaded[0]->getAlgorithm());
        $this->assertEquals('RS512', $loaded[1]->getAlgorithm());
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpiredJWS()
    {
        $loader = $this->getLoader();

        $jws = new JWS();
        $jws->setPayload(['exp' => time() - 1]);

        $loader->verify($jws);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage Can not use this JWT yet.
     */
    public function testInvalidNotBeforeJWS()
    {
        $loader = $this->getLoader();

        $jws = new JWS();
        $jws->setPayload(['nbf' => time() + 1000]);

        $loader->verify($jws);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT is issued in the futur.
     */
    public function testInvalidIssuedAtJWS()
    {
        $loader = $this->getLoader();

        $jws = new JWS();
        $jws->setPayload(['iat' => time() + 1000]);

        $loader->verify($jws);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage The claim/header 'aud' is marked as critical but value is not set.
     */
    public function testInvalidCriticalJWS()
    {
        $loader = $this->getLoader();

        $jws = new JWS();
        $jws->setProtectedHeaderValue('crit', [
            'exp',
            'nbf',
            'aud',
        ]);
        $jws->setUnprotectedHeaderValue('exp', time() + 100);
        $jws->setProtectedHeaderValue('nbf', time() - 100);

        $loader->verify($jws);
    }

    /**
     *
     */
    public function testSignAndLoadJWKSet()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $instruction1 = new SignatureInstruction();
        $instruction1->setKey($this->getKey1())
                     ->setProtectedHeader(['alg'   => 'HS512'])
                     ->setUnprotectedHeader(['foo' => 'bar']);

        $instruction2 = new SignatureInstruction();
        $instruction2->setKey($this->getKey2())
                     ->setProtectedHeader(['alg' => 'RS512']);

        $signatures = $signer->sign($this->getKeyset(), [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);
        $this->assertTrue(is_string($signatures));

        $loaded = $loader->load($signatures);

        /*
         * @var \Jose\JWSInterface[] $loaded
         */
        $this->assertTrue(is_array($loaded));
        $this->assertEquals(2, count($loaded));
        foreach ($loaded as $jws) {
            $this->assertInstanceOf('\Jose\JWSInterface', $jws);
            $this->assertEquals($this->getKeyset(), $jws->getPayload());
            $this->assertTrue($loader->verifySignature($jws));
        }
        $this->assertEquals('HS512', $loaded[0]->getAlgorithm());
        $this->assertEquals('RS512', $loaded[1]->getAlgorithm());
    }

    /**
     * @return JWK
     */
    protected function getKey1()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getKey2()
    {
        $key = new JWK([
            'kty' => 'RSA',
            'n'   => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'   => 'AQAB',
            'd'   => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'   => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'   => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'  => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'  => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'  => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getKey3()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'   => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWKSet
     */
    protected function getKeyset()
    {
        $keyset = new JWKSet();
        $keyset->addKey($this->getKey1())
               ->addKey($this->getKey2());

        return $keyset;
    }
}
