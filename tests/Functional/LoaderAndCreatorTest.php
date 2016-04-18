<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWTCreator;
use Jose\Factory\JWTLoader;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Test\TestCase;

/**
 * @group JWTLoader
 * @group JWTCreator
 * @group Functional
 */
class LoaderAndCreatorTest extends TestCase
{
    public function testSignAndLoadUsingJWTCreatorAndJWTLoader()
    {
        $checker = \Jose\Factory\CheckerManagerFactory::createClaimCheckerManager();
        $jwt_creator = new JWTCreator(['HS512'], $this->getLogger());
        $jwt_creator->enableEncryptionSupport(['A256GCMKW'], ['A128CBC-HS256'], ['DEF']);

        $jwt_loader = new JWTLoader($checker, ['HS512', 'RS512'], $this->getLogger());
        $jwt_loader->enableEncryptionSupport(['A256GCMKW'], ['A128CBC-HS256'], ['DEF']);

        $jws = $jwt_creator->sign(
            'Live long and Prosper.',
            [
                'alg' => 'HS512',
            ],
            new JWK([
                'kty' => 'oct',
                'k'   => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
            ])
        );
        $jwe = $jwt_creator->encrypt(
            $jws,
            [
                'alg' => 'A256GCMKW',
                'enc' => 'A128CBC-HS256',
            ],
            new JWK([
                'kty' => 'oct',
                'use' => 'enc',
                'k'   => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
            ])
        );

        $key_set = new JWKSet([
            'keys' => [
                [
                    'kty' => 'oct',
                    'k'   => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
                ],
                [
                    'kty' => 'oct',
                    'k'   => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
                ],
            ],
        ]);
        $loaded_jwe = $jwt_loader->load(
            $jwe,
            ['A256GCMKW'],
            ['A128CBC-HS256'],
            $key_set,
            true
        );
        $jwt_loader->verifySignature($loaded_jwe, $key_set, ['HS512']);
    }
}
