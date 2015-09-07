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
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A128GCM;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A192GCM;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A256GCM;

/**
 * Class AESGCMContentEncryptionTest.
 */
class AESGCMContentEncryptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testA128GCMEncryptAndDecrypt()
    {
        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestIncomplete('Crypto extension not available');
            return;
        }
        $header = Base64Url::encode(json_encode(['alg' => 'ECDH-ES', 'enc' => 'A128GCM']));
        $tag = null;

        $algorithm = new A128GCM();

        $cek = openssl_random_pseudo_bytes(128 / 8);
        $iv = openssl_random_pseudo_bytes(96 / 8);
        $plaintext = 'Je suis Charlie';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        $this->assertNotNull($tag);
        $this->assertEquals($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    /**
     *
     */
    public function testA192GCMEncryptAndDecrypt()
    {
        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestIncomplete('Crypto extension not available');
            return;
        }
        $header = Base64Url::encode(json_encode(['alg' => 'ECDH-ES', 'enc' => 'A192GCM']));
        $tag = null;

        $algorithm = new A192GCM();

        $cek = openssl_random_pseudo_bytes(192 / 8);
        $iv = openssl_random_pseudo_bytes(96 / 8);
        $plaintext = 'Je suis Charlie';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        $this->assertNotNull($tag);
        $this->assertEquals($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    /**
     *
     */
    public function testA256GCMEncryptAndDecrypt()
    {
        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestIncomplete('Crypto extension not available');
            return;
        }
        $header = Base64Url::encode(json_encode(['alg' => 'ECDH-ES', 'enc' => 'A256GCM']));
        $tag = null;

        $algorithm = new A256GCM();

        $cek = openssl_random_pseudo_bytes(256 / 8);
        $iv = openssl_random_pseudo_bytes(96 / 8);
        $plaintext = 'Je suis Charlie';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        $this->assertNotNull($tag);
        $this->assertEquals($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.1
     */
    public function testA256GCMDecryptTestVector()
    {
        if (!$this->isCryptooExtensionInstalled()) {
            $this->markTestIncomplete('Crypto extension not available');
            return;
        }
        $algorithm = new A256GCM();

        $header = Base64Url::encode(json_encode(['alg' => 'RSA-OAEP', 'enc' => 'A256GCM']));
        $cek = $this->convertArrayToBinString([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]);
        $iv = $this->convertArrayToBinString([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
        $tag = $this->convertArrayToBinString([92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145]);
        $cyphertext = $this->convertArrayToBinString([229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122, 233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192]);
        $expected_plaintext = 'The true sign of intelligence is not knowledge but imagination.';

        $this->assertEquals('eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ', $header);
        $this->assertEquals($expected_plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    /**
     * @param array $data
     *
     * @return string
     */
    private function convertArrayToBinString(array $data)
    {
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }

        return hex2bin(implode('', $data));
    }

    private function isCryptooExtensionInstalled()
    {
        return class_exists('\Crypto\Cipher');
    }
}
