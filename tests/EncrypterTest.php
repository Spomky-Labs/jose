<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\tests;

use Base64Url\Base64Url;
use Jose\JSONSerializationModes;
use SpomkyLabs\Jose\EncryptionInstruction;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;

/**
 * Class EncrypterTest.
 */
class EncrypterTest extends TestCase
{
    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithAAD()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getRSARecipientKey());

        $encrypted = $encrypter->encrypt(
            $this->getKeyToEncrypt(),
            [$instruction],
            ['kid' => '123456789', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertInstanceOf("Jose\JWKInterface", $loaded->getPayload());
        $this->assertEquals('RSA-OAEP-256', $loaded->getAlgorithm());
        $this->assertEquals('A256CBC-HS512', $loaded->getEncryptionAlgorithm());
        $this->assertEquals('DEF', $loaded->getZip());
        $this->assertEquals($this->getKeyToEncrypt(), $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithDeflateCompression()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getRSARecipientKey());

        $encrypted = $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'enc' => 'A128CBC-HS256', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertInstanceOf("Jose\JWKInterface", $loaded->getPayload());
        $this->assertEquals('RSA-OAEP-256', $loaded->getAlgorithm());
        $this->assertEquals('A128CBC-HS256', $loaded->getEncryptionAlgorithm());
        $this->assertEquals('DEF', $loaded->getZip());
        $this->assertEquals($this->getKeyToEncrypt(), $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactWithDirectKeyEncryption()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getDirectKey());

        $encrypted = $encrypter->encrypt($this->getKeySetToEncrypt(), [$instruction], ['kid' => 'DIR_1', 'enc' => 'A192CBC-HS384', 'alg' => 'dir'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertInstanceOf("Jose\JWKSetInterface", $loaded->getPayload());
        $this->assertEquals('dir', $loaded->getAlgorithm());
        $this->assertEquals('A192CBC-HS384', $loaded->getEncryptionAlgorithm());
        $this->assertNull($loaded->getZip());
        $this->assertEquals($this->getKeySetToEncrypt(), $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreement()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getECDHRecipientPublicKey())
                    ->setSenderKey($this->getECDHSenderPrivateKey());

        $encrypted = $encrypter->encrypt(['user_id' => '1234', 'exp' => 3600], [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('ECDH-ES', $loaded->getAlgorithm());
        $this->assertEquals('A192CBC-HS384', $loaded->getEncryptionAlgorithm());
        $this->assertNull($loaded->getZip());
        $this->assertEquals(['user_id' => '1234', 'exp' => 3600], $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingCompact()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getECDHRecipientPublicKey())
                    ->setSenderKey($this->getECDHSenderPrivateKey());

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getAlgorithm());
        $this->assertEquals('A256CBC-HS512', $loaded->getEncryptionAlgorithm());
        $this->assertNull($loaded->getZip());
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingFlattened()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getECDHRecipientPublicKey())
                    ->setSenderKey($this->getECDHSenderPrivateKey());

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getAlgorithm());
        $this->assertEquals('A256CBC-HS512', $loaded->getEncryptionAlgorithm());
        $this->assertNull($loaded->getZip());
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrapping()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction1 = new EncryptionInstruction();
        $instruction1->setRecipientKey($this->getECDHRecipientPublicKey());
        $instruction1->setSenderKey($this->getECDHSenderPrivateKey());
        $instruction1->setRecipientUnprotectedHeader(['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']);

        $instruction2 = new EncryptionInstruction();
        $instruction2->setRecipientKey($this->getRSARecipientKey());
        $instruction2->setRecipientUnprotectedHeader(['kid' => '123456789', 'alg' => 'RSA-OAEP-256']);

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction1, $instruction2], ['enc' => 'A256CBC-HS512'], [], JSONSerializationModes::JSON_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        /*
         * @var \Jose\JWEInterface[] $loaded
         */
        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf("Jose\JWEInterface", $loaded[0]);
        $this->assertTrue(is_string($loaded[0]->getPayload()));
        $this->assertEquals('ECDH-ES+A256KW', $loaded[0]->getAlgorithm());
        $this->assertEquals('A256CBC-HS512', $loaded[0]->getEncryptionAlgorithm());
        $this->assertNull($loaded[0]->getZip());
        $this->assertEquals('Je suis Charlie', $loaded[0]->getPayload());

        $this->assertInstanceOf("Jose\JWEInterface", $loaded[1]);
        $this->assertTrue(is_string($loaded[1]->getPayload()));
        $this->assertEquals('RSA-OAEP-256', $loaded[1]->getAlgorithm());
        $this->assertEquals('A256CBC-HS512', $loaded[1]->getEncryptionAlgorithm());
        $this->assertNull($loaded[1]->getZip());
        $this->assertEquals('Je suis Charlie', $loaded[1]->getPayload());
    }

    /**
     * @return JWK
     */
    protected function getKeyToEncrypt()
    {
        $key = new JWK();
        $key->setValues([
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
    protected function getKeySetToEncrypt()
    {
        $key = new JWK();
        $key->setValues([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'   => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $key_set = new JWKSet();
        $key_set->addKey($key);

        return $key_set;
    }

    /**
     * @return JWK
     */
    protected function getRSARecipientKey()
    {
        $key = new JWK();
        $key->setValues([
            'kty' => 'RSA',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getECDHRecipientPublicKey()
    {
        $key = new JWK();
        $key->setValues([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getECDHSenderPrivateKey()
    {
        $key = new JWK();
        $key->setValues([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getDirectKey()
    {
        $key = new JWK();
        $key->setValues([
            'kid' => 'DIR_1',
            'kty' => 'dir',
            'dir' => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
        ]);

        return $key;
    }
}
