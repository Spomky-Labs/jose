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
use Jose\Algorithm\KeyEncryption\ECDHES;
use Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Object\JWK;

/**
 * Class ECDHESKeyAgreementTest.
 *
 * @group ECDHES
 */
class ECDHESKeyAgreementTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    public function testGetAgreementKey()
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd',
        ]);

        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];
        $expected = Base64Url::decode('9FdsD3uzmeK4ImyoWpP5PA');
        $ecdh_es = new ECDHES();
        $additional_header_values = [];

        $this->assertEquals($expected, $ecdh_es->getAgreementKey(128, $sender, $receiver, $header, $additional_header_values));
        $this->assertTrue(array_key_exists('epk', $additional_header_values));
        $this->assertTrue(array_key_exists('kty', $additional_header_values['epk']));
        $this->assertTrue(array_key_exists('crv', $additional_header_values['epk']));
        $this->assertTrue(array_key_exists('x', $additional_header_values['epk']));
        $this->assertTrue(array_key_exists('y', $additional_header_values['epk']));
    }

    /**
     *
     */
    public function testGetAgreementKeyWithA128KeyWrap()
    {
        $header = ['enc' => 'A128GCM'];

        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA128KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($sender, $receiver, $cek, 128, $header, $header);
        $this->assertTrue(array_key_exists('epk', $header));
        $this->assertTrue(array_key_exists('crv', $header['epk']));
        $this->assertTrue(array_key_exists('kty', $header['epk']));
        $this->assertTrue(array_key_exists('x', $header['epk']));
        $this->assertTrue(array_key_exists('y', $header['epk']));
        $this->assertEquals('P-256', $header['epk']['crv']);
        $this->assertEquals('EC', $header['epk']['kty']);
        $this->assertEquals($cek, $ecdh_es->unwrapAgreementKey($receiver, $encrypted_cek, 128, $header));
    }

    /**
     *
     */
    public function testGetAgreementKeyWithA192KeyWrap()
    {
        $header = ['enc' => 'A192GCM'];
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA192KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($sender, $receiver, $cek, 192, $header, $header);
        $this->assertTrue(array_key_exists('epk', $header));
        $this->assertTrue(array_key_exists('crv', $header['epk']));
        $this->assertTrue(array_key_exists('kty', $header['epk']));
        $this->assertTrue(array_key_exists('x', $header['epk']));
        $this->assertTrue(array_key_exists('y', $header['epk']));
        $this->assertEquals('P-256', $header['epk']['crv']);
        $this->assertEquals('EC', $header['epk']['kty']);
        $this->assertEquals($cek, $ecdh_es->unwrapAgreementKey($receiver, $encrypted_cek, 192, $header));
    }

    /**
     *
     */
    public function testGetAgreementKeyWithA256KeyWrap()
    {
        $header = ['enc' => 'A256GCM'];
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA256KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($sender, $receiver, $cek, 256, $header, $header);
        $this->assertTrue(array_key_exists('epk', $header));
        $this->assertTrue(array_key_exists('crv', $header['epk']));
        $this->assertTrue(array_key_exists('kty', $header['epk']));
        $this->assertTrue(array_key_exists('x', $header['epk']));
        $this->assertTrue(array_key_exists('y', $header['epk']));
        $this->assertEquals('P-256', $header['epk']['crv']);
        $this->assertEquals('EC', $header['epk']['kty']);
        $this->assertEquals($cek, $ecdh_es->unwrapAgreementKey($receiver, $encrypted_cek, 256, $header));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Curves are different
     */
    public function testCurvesAreDifferent()
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender, $receiver);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "epk" parameter missing
     */
    public function testEPKParameterAreMissing()
    {
        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "epk" parameter is not an array of parameter
     */
    public function testBadEPKParameter()
    {
        $header = ['epk' => 'foo'];
        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender, null, $header);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key must be private
     */
    public function testNotAPrivateKey()
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender, $receiver);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key type must be "EC"
     */
    public function testNotAnECKey()
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $sender = new JWK([
            'kty' => 'dir',
            'dir' => Base64Url::encode('ABCD'),
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender, $receiver);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key components ("x", "y" or "crv") missing
     */
    public function testECKeyHasMissingParameters()
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'dir' => Base64Url::encode('ABCD'),
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, $sender, $receiver);
    }

    public function testGetAnAgreementKeyUsingP521Keys()
    {
        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'd'   => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x'   => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y'   => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);

        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(256, $sender, $receiver, $header);
        $this->assertEquals('clNz59mGIo1vb1wRLUz7FYB2pGx3TpQ-pRiqdEPdW1o', Base64Url::encode($agreement_key));
    }

    public function testGetAnAgreementKeyUsingP384Keys()
    {
        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-384',
            'x'   => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y'   => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-384',
            'd'   => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x'   => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y'   => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);

        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(256, $sender, $receiver, $header);
        $this->assertEquals('-Fj6ZkBpOcITxDcloKVNItlIH6qF2gyjw7oIHIEChp8', Base64Url::encode($agreement_key));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Curve "P-192" is not supported
     */
    public function testUnsupportedCurve()
    {
        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-192',
            'x'   => 'm2Jmp98NRH83ramvp0VVIQJXK56ZEwuM',
            'y'   => '84lz6hQtPJe9WFPPgEyOUwh3tuW2kOS_',
        ]);

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-192',
            'd'   => 'qArdbBWdouFDDNNu0KQn5LvlC_2sUX2Y',
            'x'   => 'oiSisKljjDC_KrqGQl0WvxLvDOAxbKdL',
            'y'   => '97zCNl8vB9uiDcRhoH19DnplN0KSRn9A',
        ]);

        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(256, $sender, $receiver, $header);
        $this->assertEquals('-Fj6ZkBpOcITxDcloKVNItlIH6qF2gyjw7oIHIEChp8', Base64Url::encode($agreement_key));
    }
}
