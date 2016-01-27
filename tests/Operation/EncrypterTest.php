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
use Jose\Factory\DecrypterFactory;
use Jose\Factory\EncrypterFactory;
use Jose\Factory\JWEFactory;
use Jose\Loader;
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
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF'], $this->getCheckers());

        $jwe = JWEFactory::createJWE('FOO', 'foo,bar,baz');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $jwe = $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );

        $encrypted = $jwe->toFlattenedJSON(0);

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertEquals('FOO', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithAAD()
    {
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF'], $this->getCheckers());

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt(), 'foo,bar,baz');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $jwe = $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );

        $encrypted = $jwe->toFlattenedJSON(0);

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeyToEncrypt(), new JWK($loaded->getPayload()));
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Compression method "FIP" not supported
     */
    public function testCompressionAlgorithmNotSupported()
    {
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt(), 'foo,bar,baz');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'FIP'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );
    }

    /**
     *
     */
    public function testMultipleInstructionsNotAllowedWithCompactSerialization()
    {
        $this->markTestIncomplete('Should be OK now');

        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP', 'A256CBC-HS512'], ['DEF' => 0]);

        $instruction1 = new EncryptionInstruction(
            $this->getRSARecipientKeyWithAlgorithm()
        );

        $instruction2 = new EncryptionInstruction(
            $this->getRSARecipientKey()
        );

        $result = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP',
            ],
            []
        );

        $this->assertTrue(is_array($result));
        $this->assertEquals(2, count($result));
    }

    /**
     *
     */
    public function testMultipleInstructionsNotAllowedWithFlattenedSerialization()
    {
        $this->markTestIncomplete('Should be OK now');

        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF' => 0]);

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

        $result = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            ['enc' => 'A256CBC-HS512'],
            []
        );

        $this->assertTrue(is_array($result));
        $this->assertEquals(2, count($result));
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Foreign key management mode forbidden.
     */
    public function testMultipleInstructionsNotAllowedWithFlattenedSerialization2()
    {
        $this->markTestIncomplete('Should be OK now');

        $encrypter = EncrypterFactory::createEncrypter(['dir', 'ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF' => 0]);

        $instruction1 = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );

        $instruction2 = new EncryptionInstruction(
            $this->getDirectKey(),
            null,
            ['kid' => 'DIR_1', 'alg' => 'dir']
        );

        $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            ['enc' => 'A256CBC-HS512'],
            []
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to encrypt
     */
    public function testOperationNotAllowedForTheKey()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE('Foo', 'foo,bar,baz');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getSigningKey()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key is only allowed for algorithm "RSA-OAEP-256".
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A256CBC-HS512'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE('FOO', 'foo,bar,baz');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKeyWithAlgorithm()
        );
    }

    /**
     *
     */
    public function testEncryptAndLoadFlattenedWithDeflateCompression()
    {
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'A128CBC-HS256'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['RSA-OAEP-256', 'A128CBC-HS256'], ['DEF'], $this->getCheckers());

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A128CBC-HS256',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $jwe = $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );

        $encrypted = $jwe->toFlattenedJSON(0);

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeySetToEncrypt(), new JWKSet($loaded->getPayload()));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "alg" is missing.
     */
    public function testAlgParameterIsMissing()
    {
        $encrypter = EncrypterFactory::createEncrypter(['A128CBC-HS256'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A256CBC-HS512',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "enc" is missing.
     */
    public function testEncParameterIsMissing()
    {
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key encryption algorithm "A256CBC-HS512" is not supported or not a key encryption algorithm instance.
     */
    public function testNotAKeyEncryptionAlgorithm()
    {
        $encrypter = EncrypterFactory::createEncrypter(['A128CBC-HS256'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A256CBC-HS512',
            'alg' => 'A256CBC-HS512',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The algorithm "RSA-OAEP-256" is not enabled or does not implement ContentEncryptionInterface.
     */
    public function testNotAContentEncryptionAlgorithm()
    {
        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256'], ['DEF' => 0]);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'RSA-OAEP-256',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF'
        ]);

        $encrypter->addRecipient(
            $jwe,
            $this->getRSARecipientKey()
        );
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactWithDirectKeyEncryption()
    {
        $encrypter = EncrypterFactory::createEncrypter(['dir', 'A192CBC-HS384'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['dir', 'A192CBC-HS384'], ['DEF'], $this->getCheckers());

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => 'DIR_1',
            'enc' => 'A192CBC-HS384',
            'alg' => 'dir',
        ]);

        $jwe = $encrypter->addRecipient(
            $jwe,
            $this->getDirectKey()
        );

        $encrypted = $jwe->toFlattenedJSON(0);

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('dir', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeader('enc'));
        $this->assertFalse($loaded->hasSharedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeySetToEncrypt(), new JWKSet($loaded->getPayload()));
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreement()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES', 'A192CBC-HS384'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['ECDH-ES', 'A192CBC-HS384'], ['DEF'], $this->getCheckers());

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(
            ['user_id' => '1234', 'exp' => time() + 3600],
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES'],
            []
        );

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES', $loaded->getHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

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
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES', 'A192CBC-HS384'], ['DEF' => 0]);

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey()
        );

        $encrypter->encrypt(
            ['user_id' => '1234', 'exp' => time() + 3600],
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES'],
            []
        );
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.
     */
    public function testEncryptWithAgreementKeyWrapAlgorithm()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['A192CBC-HS384', 'ECDH-ES+A128KW'], ['DEF' => 0]);

        $instruction = new EncryptionInstruction($this->getECDHRecipientPublicKey());

        $encrypter->encrypt(
            ['user_id' => '1234', 'exp' => 3600],
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES+A128KW'],
            []
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No instruction
     */
    public function testNoInstruction()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['A192CBC-HS384', 'ECDH-ES+A128KW'], ['DEF' => 0]);

        $encrypter->encrypt(
            ['user_id' => '1234', 'exp' => 3600],
            [],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A192CBC-HS384', 'alg' => 'ECDH-ES+A128KW'],
            []
        );
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingCompact()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF'], $this->getCheckers());

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'],
            []
        );

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrappingFlattened()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF'], $this->getCheckers());

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256CBC-HS512', 'alg' => 'ECDH-ES+A256KW'],
            []
        );

        $loaded = Loader::load($encrypted);

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadWithGCMAndAAD()
    {
        $this->markTestIncomplete('To be fixed');

        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestSkipped('Crypto extension not available');

            return;
        }

        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES+A256KW', 'A256GCM'], ['DEF' => 0]);

        $instruction = new EncryptionInstruction(
            $this->getECDHRecipientPublicKey(),
            $this->getECDHSenderPrivateKey()
        );

        $encrypted = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction],
            JSONSerializationModes::JSON_FLATTENED_SERIALIZATION,
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'enc' => 'A256GCM', 'alg' => 'ECDH-ES+A256KW'],
            [],
            'foo,bar,baz');

        $loaded = Loader::load($encrypted);
        $decrypter = DecrypterFactory::createDecrypter(['A256GCM', 'ECDH-ES+A256KW'], ['DEF'], $this->getCheckers());

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getHeader('alg'));
        $this->assertEquals('A256GCM', $loaded->getHeader('enc'));
        $this->assertFalse($loaded->hasHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
    }

    /**
     *
     */
    public function testEncryptAndLoadCompactKeyAgreementWithWrapping()
    {
        $this->markTestIncomplete('To be fixed');

        $encrypter = EncrypterFactory::createEncrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF' => 0]);
        $decrypter = DecrypterFactory::createDecrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW', 'A256CBC-HS512'], ['DEF'], $this->getCheckers());

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

        $encrypted = $encrypter->encrypt(
            'Je suis Charlie',
            [$instruction1, $instruction2],
            JSONSerializationModes::JSON_SERIALIZATION,
            ['enc' => 'A256CBC-HS512'],
            []
        );

        $loaded = Loader::load($encrypted);

        /*
         * @var \Jose\Object\JWEInterface[] $loaded
         */
        $this->assertEquals(2, count($loaded));

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded[0]);
        $this->assertEquals('ECDH-ES+A256KW', $loaded[0]->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded[0]->getHeader('enc'));
        $this->assertFalse($loaded[0]->hasHeader('zip'));
        $this->assertNull($loaded[0]->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet());

        $this->assertTrue($result);
        $this->assertTrue(is_string($loaded[0]->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded[0]->getPayload());

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded[1]);
        $this->assertEquals('RSA-OAEP-256', $loaded[1]->getHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded[1]->getHeader('enc'));
        $this->assertFalse($loaded[1]->hasHeader('zip'));
        $this->assertNull($loaded[1]->getPayload());

        $this->assertFalse($decrypter->decryptUsingKeySet($loaded[1], new JWKSet()));
        $this->assertFalse($decrypter->decryptUsingKeySet($loaded[1], $this->getSymmetricKeySet()));
        $this->assertTrue($decrypter->decryptUsingKeySet($loaded[1], $this->getPrivateKeySet()));
        $this->assertTrue(is_string($loaded[1]->getPayload()));
        $this->assertEquals('Je suis Charlie', $loaded[1]->getPayload());
    }

    /**
     * @return JWK
     */
    private function getKeyToEncrypt()
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
    private function getKeySetToEncrypt()
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
    private function getRSARecipientKey()
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
    private function getRSARecipientKeyWithAlgorithm()
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
    private function getSigningKey()
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
    private function getECDHRecipientPublicKey()
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
    private function getECDHSenderPrivateKey()
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
    private function getDirectKey()
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
