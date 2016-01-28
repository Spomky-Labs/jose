<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWSFactory;
use Jose\Factory\SignerFactory;
use Jose\Factory\VerifierFactory;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Test\TestCase;

/**
 * @group Signer
 */
class SignerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No "alg" parameter set in the header.
     */
    public function testAlgParameterIsMissing()
    {
        $signer = SignerFactory::createSigner([]);

        $jws = JWSFactory::createJWS($this->getKey3());
        $signer->addSignature(
            $jws,
            $this->getKey1()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "foo" is not supported.
     */
    public function testAlgParameterIsNotSupported()
    {
        $signer = SignerFactory::createSigner([]);

        $jws = JWSFactory::createJWS($this->getKey3());
        $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'foo']
        );
    }

    /**
     *
     */
    public function testSignAndLoadCompact()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);

        $jws = JWSFactory::createJWS($this->getKey3());
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $this->assertEquals(2, $jws->countSignatures());

        $loaded = Loader::load($jws->toJSON());

        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    /**
     *
     */
    public function testSignMultipleInstructionWithCompactRepresentation()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);

        $jws = JWSFactory::createJWS('Je suis Charlie');
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9.SmUgc3VpcyBDaGFybGll.di3mwSN9cb9OTIJ-V53TMlX6HiCZQnvP9uFTCF4NPXOnPsmH_M74vIUr3O_jpkII1Bim6aUZVlzmhwfsUpAazA', $jws->toCompactJSON(0));
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9.SmUgc3VpcyBDaGFybGll.JFGAhEsQvMYOAfV5ShYK3Z_VS0Lz-jhwmucIudCT9gtSMdv1B4NTJfvuEnGkPnGCTW0j09eZxJSkT6-iU2YlyN22LD9nGuxCzBPLrz3JFETRNws77jfc2F7Jcc3MfCA5yhRbTZuyVL02LoQhOlgFvuUz9VaNuPCogarU3UxOgu1VPnrb2VMi6HCXHylmrSrQBrHShYtW0KEEkmN4X6HLtebnAuFIwhe8buy-aDURmFeqq2a6v92v69v1bqqZYA6YkOU5OzA-VLC8-MYM4ltFEUvGUPB3NGztg7r0QjImDdI5S13yV4IXsl6_XEgi3ilUXI1-tYgwZssSaRPdiOCBUg', $jws->toCompactJSON(1));
    }

    /**
     *
     */
    public function testSignMultipleInstructionWithFlattenedRepresentation()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);

        $jws = JWSFactory::createJWS('Je suis Charlie');
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('{"payload":"SmUgc3VpcyBDaGFybGll","protected":"eyJhbGciOiJIUzUxMiJ9","signature":"di3mwSN9cb9OTIJ-V53TMlX6HiCZQnvP9uFTCF4NPXOnPsmH_M74vIUr3O_jpkII1Bim6aUZVlzmhwfsUpAazA"}', $jws->toFlattenedJSON(0));
        $this->assertEquals('{"payload":"SmUgc3VpcyBDaGFybGll","protected":"eyJhbGciOiJSUzUxMiJ9","signature":"JFGAhEsQvMYOAfV5ShYK3Z_VS0Lz-jhwmucIudCT9gtSMdv1B4NTJfvuEnGkPnGCTW0j09eZxJSkT6-iU2YlyN22LD9nGuxCzBPLrz3JFETRNws77jfc2F7Jcc3MfCA5yhRbTZuyVL02LoQhOlgFvuUz9VaNuPCogarU3UxOgu1VPnrb2VMi6HCXHylmrSrQBrHShYtW0KEEkmN4X6HLtebnAuFIwhe8buy-aDURmFeqq2a6v92v69v1bqqZYA6YkOU5OzA-VLC8-MYM4ltFEUvGUPB3NGztg7r0QjImDdI5S13yV4IXsl6_XEgi3ilUXI1-tYgwZssSaRPdiOCBUg"}', $jws->toFlattenedJSON(1));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "RS512" is allowed with this key.
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $signer = SignerFactory::createSigner([]);

        $jws = JWSFactory::createJWS('Je suis Charlie');
        $signer->addSignature(
            $jws,
            $this->getKey5(),
            ['alg' => 'RS512']
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to sign
     */
    public function testOperationNotAllowedForTheKey()
    {
        $signer = SignerFactory::createSigner(['PS512']);

        $jws = JWSFactory::createJWS('Je suis Charlie');
        $signer->addSignature(
            $jws,
            $this->getKey4(),
            ['alg' => 'PS512']
        );
    }

    /**
     *
     */
    public function testSignAndLoadFlattened()
    {
        $signer = SignerFactory::createSigner(['HS512']);

        $jws = JWSFactory::createJWS(['baz', 'ban']);
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512'],
            ['foo' => 'bar']
        );

        $loaded = Loader::load($jws->toJSON());

        $this->assertEquals(1, $loaded->countSignatures());
        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
    }

    /**
     *
     */
    public function testSignAndLoad()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);
        $verifier = VerifierFactory::createVerifier(['HS512', 'RS512'], $this->getCheckers());

        $jws = JWSFactory::createJWS('Je suis Charlie');
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512'],
            ['foo' => 'bar']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $loaded = Loader::load($jws->toJSON());

        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
        $this->assertTrue($verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet()));
        $this->assertTrue($verifier->verifyWithKeySet($loaded, $this->getPublicKeySet()));

        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    /**
     *
     */
    public function testSignAndLoadJWKSet()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);
        $verifier = VerifierFactory::createVerifier(['HS512', 'RS512'], $this->getCheckers());

        $jws = JWSFactory::createJWS($this->getKeyset());
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512'],
            ['foo' => 'bar']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $loaded = Loader::load($jws->toJSON());
        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertEquals($this->getKeyset(), new JWKSet($loaded->getPayload()));
        $this->assertTrue($verifier->verifyWithKeySet($loaded, $this->getPublicKeySet()));
        $this->assertTrue($verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet()));

        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No key in the key set.
     */
    public function testKeySetIsEmpty()
    {
        $signer = SignerFactory::createSigner(['HS512', 'RS512']);
        $verifier = VerifierFactory::createVerifier(['HS512', 'RS512'], $this->getCheckers());

        $jws = JWSFactory::createJWS($this->getKeyset());
        $jws = $signer->addSignature(
            $jws,
            $this->getKey1(),
            ['alg' => 'HS512'],
            ['foo' => 'bar']
        );
        $jws = $signer->addSignature(
            $jws,
            $this->getKey2(),
            ['alg' => 'RS512']
        );

        $loaded = Loader::load($jws->toJSON());
        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf('\Jose\Object\JWSInterface', $loaded);
        $this->assertEquals($this->getKeyset(), new JWKSet($loaded->getPayload()));
        $this->assertFalse($verifier->verifyWithKeySet($loaded, new JWKSet()));
    }

    /**
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKSetInterface
     */
    protected function getKeyset()
    {
        $keyset = new JWKSet();
        $keyset = $keyset->addKey($this->getKey1());
        $keyset = $keyset->addKey($this->getKey2());

        return $keyset;
    }
}
