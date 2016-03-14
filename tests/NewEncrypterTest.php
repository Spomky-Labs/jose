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
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Test\TestCase;
use Jose\Test\Stub\FakeLogger;
use Jose\Object\Recipient;

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
            'Je suis Charlie',
            [
                'enc' => 'A256CBC-HS512',
            ], [
                'zip' => 'DEF',
            ]
        );

        $recipient = Recipient::createRecipientForJWEEncryption(
            $this->getSharedKey(),
            [
                'alg' => 'A256GCMKW',
            ]
        );

        $jwe = $jwe->addRecipient($recipient);

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
        $this->assertEquals('Je suis Charlie', $loaded->getPayload());
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
}
