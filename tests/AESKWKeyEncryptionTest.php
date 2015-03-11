<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use Base64Url\Base64Url;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A256KW;

/**
 * Class AESKWKeyEncryptionTest.
 */
class AESKWKeyEncryptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testA128KW()
    {
        $header = array();
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => Base64Url::encode(hex2bin("000102030405060708090A0B0C0D0E0F")),
        ));

        $cek = hex2bin("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        $aeskw = new A128KW();

        $wrapped_cek = $aeskw->encryptKey($key, $cek, $header);

        $this->assertEquals($wrapped_cek, hex2bin('11826840774D993FF9C2FA02CCA3CEA0E93B1E1CF96361F93EA6DC2F345194E7B30F964C79F9E61D'));
        $this->assertEquals($cek, $aeskw->decryptKey($key, $wrapped_cek, $header));
    }

    /**
     *
     */
    public function testA192KW()
    {
        $header = array();
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => Base64Url::encode(hex2bin("000102030405060708090A0B0C0D0E0F1011121314151617")),
        ));

        $cek = hex2bin("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        $aeskw = new A192KW();

        $wrapped_cek = $aeskw->encryptKey($key, $cek, $header);

        $this->assertEquals($wrapped_cek, hex2bin('08861E000AABFA4479C7191F9DC51CCA37C50F16CC14441C6EA4980CFCE0F41D9285758C6F74AC6D'));
        $this->assertEquals($cek, $aeskw->decryptKey($key, $wrapped_cek, $header));
    }

    /**
     *
     */
    public function testA256KW()
    {
        $header = array();
        $key = new JWK();
        $key->setValues(array(
            "kty" => "oct",
            "k"  => Base64Url::encode(hex2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")),
        ));

        $cek = hex2bin("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        $aeskw = new A256KW();

        $wrapped_cek = $aeskw->encryptKey($key, $cek, $header);

        $this->assertEquals($wrapped_cek, hex2bin('28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'));
        $this->assertEquals($cek, $aeskw->decryptKey($key, $wrapped_cek, $header));
    }
}
