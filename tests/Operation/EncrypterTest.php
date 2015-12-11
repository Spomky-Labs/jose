<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\JSONSerializationModes;
use Jose\Object\EncryptionInstruction;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Test\TestCase;

/**
 * Class EncrypterTest.
 *
 * @group Encrypter
 */
class EncrypterTest extends TestCase
{
    /**
     *
     */
    public function testEncryptWithJWTInput()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypted = $encrypter->encrypt(
            'FOO',
            [$instruction],
            ['kid' => '123456789', 'use' => 'enc', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertEquals('DEF', $loaded->getHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertEquals('FOO', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithAAD()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypted = $encrypter->encrypt(
            $this->getKeyToEncrypt(),
            [$instruction],
            ['kid' => '123456789', 'use' => 'enc', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertEquals('DEF', $loaded->getHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertEquals($this->getKeyToEncrypt(), $loaded->getPayload());
        $this->assertInstanceOf('Jose\Object\JWKInterface', $loaded->getPayload());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Compression method "FIP" not supported
     */
    public function testCompressionAlgorithmNotSupported()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypter->encrypt(
            'FOO',
            [$instruction],
            ['kid' => '123456789', 'use' => 'enc', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'FIP'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Only one instruction authorized when Compact or Flattened Serialization Overview is selected.
     */
    public function testMultipleInstructionsNotAllowedWithCompactSerialization()
    {
        $encrypter = $this->getEncrypter();

        $instruction1 = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );

        $instruction2 = new EncryptionInstruction(
            $this->getRSARecipientKey(),
            null,
            ['kid' => '123456789', 'alg' => 'RSA-OAEP-256']
        );

        $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            ['enc' => 'A256CBC-HS512'],
            [],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Only one instruction authorized when Compact or Flattened Serialization Overview is selected.
     */
    public function testMultipleInstructionsNotAllowedWithFlattenedSerialization()
    {
        $encrypter = $this->getEncrypter();

        $instruction1 = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']);

        $instruction2 = new EncryptionInstruction(
            $this->getRSARecipientKey(),
            null,
            ['kid' => '123456789', 'alg' => 'RSA-OAEP-256']
        );

        $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            ['enc' => 'A256CBC-HS512'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to encrypt
     */
    public function testOperationNotAllowedForTheKey()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getSigningKey());

        $encrypter->encrypt(
            'FOO',
            [$instruction],
            ['kid' => '123456789', 'use' => 'enc', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key is only allowed for algorithm "RSA-OAEP-256".
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKeyWithAlgorithm());

        $encrypter->encrypt(
            'FOO',
            [$instruction],
            ['kid' => '123456789', 'use' => 'enc', 'enc' => 'A256CBC-HS512', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz'
        );
    }

    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithDeflateCompression()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypted = $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'enc' => 'A128CBC-HS256', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getHeader('enc'));
        $this->assertEquals('DEF', $loaded->getHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertEquals($this->getKeyToEncrypt(), $loaded->getPayload());
        $this->assertEquals($encrypted, $loaded->getInput());
        $this->assertInstanceOf('Jose\Object\JWKInterface', $loaded->getPayload());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "alg" is missing.
     */
    public function testAlgParameterIsMissing()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'enc' => 'A128CBC-HS256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "enc" is missing.
     */
    public function testEncParameterIsMissing()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'alg' => 'RSA-OAEP-256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The key encryption algorithm "A128CBC-HS256" is not supported or not a key encryption algorithm instance.
     */
    public function testNotAKeyEncryptionAlgorithm()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'alg' => 'A128CBC-HS256', 'enc' => 'A128CBC-HS256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The algorithm "RSA-OAEP-256" does not implement ContentEncryptionInterface.
     */
    public function testNotAContentEncryptionAlgorithm()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getRSARecipientKey());

        $encrypter->encrypt($this->getKeyToEncrypt(), [$instruction], ['kid' => '123456789', 'alg' => 'RSA-OAEP-256', 'enc' => 'RSA-OAEP-256', 'zip' => 'DEF'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactWithDirectKeyEncryption()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction($this->getDirectKey());

        $encrypted = $encrypter->encrypt($this->getKeySetToEncrypt(), [$instruction], ['kid' => 'DIR_1', 'enc' => 'A192CBC-HS384', 'alg' => 'dir'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('dir', $loaded->getHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getSymmetricKeySet());

        $this->assertTrue($result);
        $this->assertEquals($this->getKeySetToEncrypt(), $loaded->getPayload());
        $this->assertInstanceOf('Jose\Object\JWKSetInterface', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreement()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(['user_id' => '1234', 'exp' => time()+3600], [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES', $loaded->getHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue($loaded->hasClaims());
        $this->assertTrue($loaded->hasClaim('user_id'));
        $this->assertEquals('1234', $loaded->getClaim('user_id'));
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.
     */
    public function testEncryptWithAgreementAlgorithm()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey()
        );

        $encrypter->encrypt(['user_id' => '1234', 'exp' => time()+3600], [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES'], []);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.
     */
    public function testEncryptWithAgreementKeyWrapAlgorithm()
    {
        $encrypter = $this->getEncrypter();

        $instruction = new EncryptionInstruction($this->getECDHRecipientPublicKey());

        $encrypter->encrypt(['user_id' => '1234', 'exp' => 3600], [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES+A128KW'], []);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No instruction
     */
    public function testNoInstruction()
    {
        $encrypter = $this->getEncrypter();

        $encrypter->encrypt(['user_id' => '1234', 'exp' => 3600], [], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES+A128KW'], []);
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingCompact()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'], []);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingFlattened()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction], ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'], [], JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadWithGCMAndAAD()
    {
        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestSkipped('Crypto extension not available');

            return;
        }
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction],
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256GCM', 'alg' => 'ECDH-ES+A256KW'],
            [],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            'foo,bar,baz');

        $loaded = $loader->load($encrypted);
        $decrypter = $this->getDecrypter();

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256GCM', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decrypt($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrapping()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();
        $decrypter = $this->getDecrypter();

        $instruction1 = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );

        $instruction2 = new EncryptionInstruction(
            $this->getRSARecipientKey(),
            null,
            ['kid' => '123456789', 'alg' => 'RSA-OAEP-256']
        );

        $encrypted = $encrypter->encrypt('Je suis Charlie', [$instruction1, $instruction2], ['enc' => 'A256CBC-HS512'], [], JSONSerializationModes::JSON_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        /*
         * @var \Jose\Object\JWEInterface[] $loaded
         */
        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded[0]);
        $this->assertEquals('ECDH-ES+A256KW', $loaded[0]->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded[0]->getHeader('enc'));
        $this->assertFalse($loaded[0]->hasHeader('zip'));
        $this->assertNull($loaded[0]->getPayload());

        $result = $decrypter->decrypt($loaded[0], $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded[0]->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded[0]->getPayload());

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded[1]);
        $this->assertEquals('RSA-OAEP-256', $loaded[1]->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded[1]->getHeader('enc'));
        $this->assertFalse($loaded[1]->hasHeader('zip'));
        $this->assertNull($loaded[1]->getPayload());

        $this->assertFalse($decrypter->decrypt($loaded[1], new JWKSet()));
        $this->assertFalse($decrypter->decrypt($loaded[1], $this->getSymmetricKeySet()));
        $this->assertTrue($decrypter->decrypt($loaded[1], $this->getPrivateKeySet()));
        $this->assertTrue(is_string($loaded[1]->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded[1]->getPayload());
    }

    /**
     * @return JWK
     */
    protected function getKeyToEncrypt()
    {
        $key = new JWK([
            'kty' => 'EC',
            'use' => 'enc',
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
        $key = new JWK([
            'kty' => 'EC',
            'use' => 'enc',
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
        $key = new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getRSARecipientKeyWithAlgorithm()
    {
        $key = new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'alg' => 'RSA-OAEP',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getSigningKey()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'key_ops' => ['sign', 'verify'],
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getECDHRecipientPublicKey()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'key_ops' => ['encrypt', 'decrypt'],
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getECDHSenderPrivateKey()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'key_ops' => ['encrypt', 'decrypt'],
            'crv'     => 'P-256',
            'x'       => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'       => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'       => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    protected function getDirectKey()
    {
        $key = new JWK([
            'kid'     => 'DIR_1',
            'key_ops' => ['encrypt', 'decrypt'],
            'kty'     => 'dir',
            'dir'     => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
        ]);

        return $key;
    }

    private function isCryptooExtensionInstalled()
    {
        return class_exists('\Crypto\Cipher');
    }
}
