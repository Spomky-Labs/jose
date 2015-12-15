<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\JSONSerializationModes;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Object\SignatureInstruction;
use Jose\Test\TestCase;

/**
 * @group Signer
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

        $signer->sign($input, [], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported input type.
     */
    public function testUnsupportedInputType()
    {
        $resource = fopen(__FILE__, 'r');
        $signer = $this->getSigner();
        $signer->sign($resource, [], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad instruction. Must implement SignatureInstructionInterface.
     */
    public function testBadInstruction()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $signer->sign($input, ['Bad instruction'], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No "alg" parameter set in the header.
     */
    public function testAlgParameterIsMissing()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction($this->getKey1());

        $signer->sign($input, [$instruction], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "foo" is not supported.
     */
    public function testAlgParameterIsNotSupported()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction($this->getKey1(), ['alg' => 'foo']);

        $signer->sign($input, [$instruction], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The serialization method "foo_serialization" is not supported.
     */
    public function testSerializationIsNotSupported()
    {
        $signer = $this->getSigner();

        $input = $this->getKey3();

        $instruction = new SignatureInstruction($this->getKey1(), ['alg' => 'HS512']);

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

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg' => 'HS512']);

        $instruction2 = new SignatureInstruction($this->getKey2(), ['alg' => 'RS512']);

        $signatures = $signer->sign($input, [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);

        $this->assertTrue(is_string($signatures));

        /*
         * @var \Jose\Object\JWSInterface[]
         */
        $loaded = $loader->load($signatures);

        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[0]);
        $this->assertInstanceOf('\Jose\Object\JWKInterface', $loaded[0]->getPayload());
        $this->assertEquals('HS512', $loaded[0]->getHeader('alg'));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[1]);
        $this->assertInstanceOf('\Jose\Object\JWKInterface', $loaded[1]->getPayload());
        $this->assertEquals('RS512', $loaded[1]->getHeader('alg'));
    }

    /**
     *
     */
    public function testSignMultipleInstructionWithCompactRepresentation()
    {
        $signer = $this->getSigner();

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg' => 'HS512']);

        $instruction2 = new SignatureInstruction($this->getKey2(), ['alg' => 'RS512']);

        $jws = $signer->sign('Je suis Charlie', [$instruction1, $instruction2], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);

        $this->assertTrue(is_array($jws));
        $this->assertEquals(2, count($jws));
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9.SmUgc3VpcyBDaGFybGll.di3mwSN9cb9OTIJ-V53TMlX6HiCZQnvP9uFTCF4NPXOnPsmH_M74vIUr3O_jpkII1Bim6aUZVlzmhwfsUpAazA', $jws[0]);
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9.SmUgc3VpcyBDaGFybGll.JFGAhEsQvMYOAfV5ShYK3Z_VS0Lz-jhwmucIudCT9gtSMdv1B4NTJfvuEnGkPnGCTW0j09eZxJSkT6-iU2YlyN22LD9nGuxCzBPLrz3JFETRNws77jfc2F7Jcc3MfCA5yhRbTZuyVL02LoQhOlgFvuUz9VaNuPCogarU3UxOgu1VPnrb2VMi6HCXHylmrSrQBrHShYtW0KEEkmN4X6HLtebnAuFIwhe8buy-aDURmFeqq2a6v92v69v1bqqZYA6YkOU5OzA-VLC8-MYM4ltFEUvGUPB3NGztg7r0QjImDdI5S13yV4IXsl6_XEgi3ilUXI1-tYgwZssSaRPdiOCBUg', $jws[1]);
    }

    /**
     *
     */
    public function testSignMultipleInstructionWithFlattenedRepresentation()
    {
        $signer = $this->getSigner();

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg' => 'HS512']);

        $instruction2 = new SignatureInstruction($this->getKey2(), ['alg' => 'RS512']);

        $jws = $signer->sign('Je suis Charlie', [$instruction1, $instruction2], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $this->assertTrue(is_array($jws));
        $this->assertEquals(2, count($jws));
        $this->assertEquals('{"payload":"SmUgc3VpcyBDaGFybGll","signature":"di3mwSN9cb9OTIJ-V53TMlX6HiCZQnvP9uFTCF4NPXOnPsmH_M74vIUr3O_jpkII1Bim6aUZVlzmhwfsUpAazA","protected":"eyJhbGciOiJIUzUxMiJ9"}', $jws[0]);
        $this->assertEquals('{"payload":"SmUgc3VpcyBDaGFybGll","signature":"JFGAhEsQvMYOAfV5ShYK3Z_VS0Lz-jhwmucIudCT9gtSMdv1B4NTJfvuEnGkPnGCTW0j09eZxJSkT6-iU2YlyN22LD9nGuxCzBPLrz3JFETRNws77jfc2F7Jcc3MfCA5yhRbTZuyVL02LoQhOlgFvuUz9VaNuPCogarU3UxOgu1VPnrb2VMi6HCXHylmrSrQBrHShYtW0KEEkmN4X6HLtebnAuFIwhe8buy-aDURmFeqq2a6v92v69v1bqqZYA6YkOU5OzA-VLC8-MYM4ltFEUvGUPB3NGztg7r0QjImDdI5S13yV4IXsl6_XEgi3ilUXI1-tYgwZssSaRPdiOCBUg","protected":"eyJhbGciOiJSUzUxMiJ9"}', $jws[1]);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "RS512" is allowed with this key.
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $signer = $this->getSigner();

        $instruction = new SignatureInstruction($this->getKey4(), ['alg' => 'RS512']);

        $signer->sign('FOO', [$instruction], JSONSerializationModes::JSON_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to sign
     */
    public function testOperationNotAllowedForTheKey()
    {
        $signer = $this->getSigner();

        $instruction = new SignatureInstruction($this->getKey4(), ['alg' => 'PS512']);

        $signer->sign('FOO', [$instruction], JSONSerializationModes::JSON_SERIALIZATION);
    }

    /**
     *
     */
    public function testSignAndLoadFlattened()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg'   => 'HS512'], ['foo' => 'bar']);

        $signatures = $signer->sign(['baz', 'ban'], [$instruction1], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $this->assertTrue(is_string($signatures));

        /*
         * @var \Jose\Object\JWSInterface
         */
        $loaded = $loader->load($signatures);

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getHeader('alg'));
    }

    /**
     *
     */
    public function testSignAndLoad()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();
        $verifier = $this->getVerifier();

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg'   => 'HS512'], ['foo' => 'bar']);

        $instruction2 = new SignatureInstruction($this->getKey2(), ['alg' => 'RS512']);

        $signatures = $signer->sign('Je suis Charlie', [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);
        $this->assertTrue(is_string($signatures));

        $loaded = $loader->load($signatures);

        /*
         * @var \Jose\Object\JWSInterface[] $loaded
         */
        $this->assertTrue(is_array($loaded));
        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[0]);
        $this->assertEquals('Je suis Charlie', $loaded[0]->getPayload());
        $this->assertTrue($verifier->verify($loaded[0], $this->getSymmetricKeySet()));
        $this->assertEquals('HS512', $loaded[0]->getHeader('alg'));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[1]);
        $this->assertEquals('Je suis Charlie', $loaded[1]->getPayload());
        $this->assertTrue($verifier->verify($loaded[1], $this->getPublicKeySet()));
        $this->assertEquals('RS512', $loaded[1]->getHeader('alg'));
    }

    /**
     *
     */
    public function testSignAndLoadJWKSet()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();
        $verifier = $this->getVerifier();

        $instruction1 = new SignatureInstruction($this->getKey1(), ['alg'   => 'HS512'], ['foo' => 'bar']);
        $instruction2 = new SignatureInstruction($this->getKey2(), ['alg' => 'RS512']);

        $signatures = $signer->sign($this->getKeyset(), [$instruction1, $instruction2], JSONSerializationModes::JSON_SERIALIZATION);
        $this->assertTrue(is_string($signatures));

        $loaded = $loader->load($signatures);

        /*
         * @var \Jose\Object\JWSInterface[] $loaded
         */
        $this->assertTrue(is_array($loaded));
        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[0]);
        $this->assertEquals($this->getKeyset(), $loaded[0]->getPayload());
        $this->assertFalse($verifier->verify($loaded[0], new JWKSet()));
        $this->assertFalse($verifier->verify($loaded[0], $this->getPublicKeySet()));
        $this->assertTrue($verifier->verify($loaded[0], $this->getSymmetricKeySet()));
        $this->assertEquals('HS512', $loaded[0]->getHeader('alg'));

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded[1]);
        $this->assertEquals($this->getKeyset(), $loaded[1]->getPayload());
        $this->assertTrue($verifier->verify($loaded[1], $this->getPublicKeySet()));
        $this->assertEquals('RS512', $loaded[1]->getHeader('alg'));
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
            'kty'     => 'RSA',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getKey3()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getKey4()
    {
        $key = new JWK([
            'kty'     => 'RSA',
            'alg'     => 'PS512',
            'key_ops' => ['encrypt', 'decrypt'],
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getKey5()
    {
        $key = new JWK([
            'kty'     => 'RSA',
            'alg'     => 'PS512',
            'use'     => 'sig',
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return JWKSet
     */
    protected function getKeyset()
    {
        $keyset = new JWKSet();
        $keyset->addKey($this->getKey1());
        $keyset->addKey($this->getKey2());

        return $keyset;
    }
}
