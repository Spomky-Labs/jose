<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\KeyConverter\RSAKey;
use Jose\KeyConverter\KeyConverter;
use Jose\Test\TestCase;

/**
 * @group RSAKeys
 */
class RSAKeysTest extends TestCase
{
    public function testLoadPublicRSAKey()
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'public.key';
        $rsa_key = new RSAKey($file);

        $this->assertEquals([
            'kty'=>'RSA',
            'n'=>'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'=>'AQAB',
        ], $rsa_key->toArray());
        $this->assertFalse($rsa_key->isPrivate());
    }
}
