<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\DecrypterFactory;
use Jose\Factory\EncrypterFactory;
use Jose\Factory\JWEFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Test\TestCase;
use Jose\Test\Stub\FakeLogger;

/**
 * Class NewEncrypterTest.
 *
 * @group NewEncrypter
 * @group Functional
 */
class NewEncrypterTest extends TestCase
{
    /**
     *
     */
    public function testEncryptWithJWTInput()
    {
        $encrypter = EncrypterFactory::createEncrypter(['A256GCMKW', 'A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = DecrypterFactory::createDecrypter(['A256GCMKW', 'A256CBC-HS512'], ['DEF'], new FakeLogger());

        $jwe = JWEFactory::createEmptyJWE(
            'Live long and Prosper.',
            [
                'enc' => 'A256CBC-HS512',
            ],
            [
                'zip' => 'DEF',
            ]
        );

        $jwe = $jwe->addRecipient(
            $this->getSharedKey(),
            [
                'alg' => 'A256GCMKW',
            ]
        );

        $encrypter->encrypt($jwe);

        $loaded = Loader::load($jwe->toJSON());

        $this->assertEquals(1, $loaded->countRecipients());

        $this->assertInstanceOf(JWEInterface::class, $loaded);
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('A256GCMKW', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertTrue($loaded->hasSharedHeader('zip'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKey($loaded, $this->getSharedKey(), $index);

        $this->assertTrue($result);
        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }
    /**
     *
     */
    public function testEncryptWithJWTInputAndDirectKey()
    {
        $encrypter = EncrypterFactory::createEncrypter(['dir', 'A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = DecrypterFactory::createDecrypter(['dir', 'A256CBC-HS512'], ['DEF'], new FakeLogger());

        $jwe = JWEFactory::createEmptyJWE(
            'Live long and Prosper.',
            [
                'enc' => 'A256CBC-HS512',
            ],
            [
                'zip' => 'DEF',
            ]
        );

        $jwe = $jwe->addRecipient(
            $this->getDirectKey(),
            [
                'alg' => 'dir',
            ]
        );

        $encrypter->encrypt($jwe);

        $loaded = Loader::load($jwe->toJSON());

        $this->assertEquals(1, $loaded->countRecipients());

        $this->assertInstanceOf(JWEInterface::class, $loaded);
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('dir', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertTrue($loaded->hasSharedHeader('zip'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKey($loaded, $this->getDirectKey(), $index);

        $this->assertTrue($result);
        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }
    /**
     *
     */
    public function testEncryptWithJWTInputAndECDHESKey()
    {
        $encrypter = EncrypterFactory::createEncrypter(['ECDH-ES', 'A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = DecrypterFactory::createDecrypter(['ECDH-ES', 'A256CBC-HS512'], ['DEF'], new FakeLogger());

        $jwe = JWEFactory::createEmptyJWE(
            'Live long and Prosper.',
            [
                'enc' => 'A256CBC-HS512',
            ],
            [
                'zip' => 'DEF',
            ]
        );

        $jwe = $jwe->addRecipient(
            $this->getPublicECKey(),
            [
                'alg' => 'ECDH-ES',
            ]
        );

        $encrypter->encrypt($jwe);

        $loaded = Loader::load($jwe->toJSON());

        $this->assertEquals(1, $loaded->countRecipients());

        $this->assertInstanceOf(JWEInterface::class, $loaded);
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('ECDH-ES', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertTrue($loaded->hasSharedHeader('zip'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKey($loaded, $this->getPrivateECKey(), $index);

        $this->assertTrue($result);
        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    /**
     * @return JWK
     */
    private function getSharedKey()
    {
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'use' => 'enc',
            'alg' => 'A256GCMKW',
            'k'   => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getDirectKey()
    {
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'use' => 'enc',
            'alg' => 'A256CBC-HS512',
            'k'   => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getPublicECKey()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getPrivateECKey()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd'   => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
        ]);

        return $key;
    }
}
