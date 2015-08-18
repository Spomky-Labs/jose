<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test;

use Base64Url\Base64Url;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHES;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use SpomkyLabs\Jose\JWK;

/**
 * Class ECDHESKeyAgreementTest.
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
}
