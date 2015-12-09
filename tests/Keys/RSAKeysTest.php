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
use Jose\Object\JWK;
use Jose\Test\TestCase;

/**
 * @group RSAKeys
 */
class RSAKeysTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported input
     */
    public function testUnsupportedInputType()
    {
        new RSAKey(1234);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage JWK is not a RSA key
     */
    public function testUnsupportedKeyType()
    {
        new RSAKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd'   => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x'   => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y'   => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    public function testLoadPublicRSAKeyFromPEM()
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'public.key';
        $rsa_key = new RSAKey($file);

        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ], $rsa_key->toArray());
        $this->assertFalse($rsa_key->isPrivate());
    }

    public function testLoadPublicRSAKeyFromJWK()
    {
        $jwk = new JWK([
            'kty'     => 'RSA',
            'n'       => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'       => 'AQAB',
            'use'     => 'sig',
            'key_ops' => ['sign', 'verify'],
        ]);
        $rsa_key = new RSAKey($jwk);

        $this->assertEquals([
            'kty'     => 'RSA',
            'n'       => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'       => 'AQAB',
            'use'     => 'sig',
            'key_ops' => ['sign', 'verify'],
        ], $rsa_key->toArray());
        $this->assertFalse($rsa_key->isPrivate());
    }

    public function testLoadPublicRSAKeyFromValues()
    {
        $rsa_key = new RSAKey([
            'kty' => 'RSA',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ], $rsa_key->toArray());
        $this->assertFalse($rsa_key->isPrivate());
    }

    public function testLoadPrivateRSAKey()
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'private.key';
        $rsa_key = new RSAKey($file);

        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());
        $this->assertTrue($rsa_key->isPrivate());

        $public_key = RSAKey::toPublic($rsa_key);
        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
        ], $public_key->toArray());
        $this->assertFalse($public_key->isPrivate());
    }

    public function testLoadPrivateRSAKeyFromJWK()
    {
        $jwk = new JWK([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ]);
        $rsa_key = new RSAKey($jwk);

        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());
        $this->assertTrue($rsa_key->isPrivate());

        $public_key = RSAKey::toPublic($rsa_key);
        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
        ], $public_key->toArray());
        $this->assertFalse($public_key->isPrivate());
    }

    public function testLoadPrivateRSAKeyFromValues()
    {
        $rsa_key = new RSAKey([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ]);

        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());

        $this->assertTrue($rsa_key->isPrivate());

        $public_key = RSAKey::toPublic($rsa_key);
        $this->assertEquals([
            'kty' => 'RSA',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
        ], $public_key->toArray());
        $this->assertFalse($public_key->isPrivate());
    }

    /**
     */
    public function testConvertPrivateKeyToPublic()
    {
        $private_ec_key = new RSAKey([
            'kty' => 'RSA',
            'kid' => 'Foo',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'p'   => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd'   => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q'   => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp'  => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq'  => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi'  => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
            'foo' => 'bar',
        ]);

        $public_ec_key = RSAKey::toPublic($private_ec_key);

        $this->assertEquals([
            'kty' => 'RSA',
            'kid' => 'Foo',
            'n'   => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e'   => 'AQAB',
            'foo' => 'bar',
        ], $public_ec_key->toArray());
    }
}
