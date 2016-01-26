<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\V2;

use Jose\Factory\EncrypterFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\JWEFactory;

/**
 * @group V2
 */
class V2EncryptionTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateJWEAndEncrypt()
    {
        $jwe = JWEFactory::createJWE('Je suis Charlie');
        $jwe = $jwe->withSharedProtectedHeaders(['alg' => 'RSA-OAEP-256', 'enc' => 'A256CBC-HS512']);
        $encrypter = EncrypterFactory::createEncrypter(['A256CBC-HS512', 'RSA-OAEP-256']);
        $recipient_key = $this->getRSARecipientKey();

        $jwe = $encrypter->addRecipient($jwe, $recipient_key);

        var_dump($jwe->toCompactJSON(0));
        var_dump($jwe->toFlattenedJSON(0));
        var_dump($jwe->toJSON());
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    protected function getRSARecipientKey()
    {
        $key = JWKFactory::createFromValues([
            'kty' => 'RSA',
            'use' => 'enc',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }
}
