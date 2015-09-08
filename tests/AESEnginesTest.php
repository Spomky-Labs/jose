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

use SpomkyLabs\Jose\Algorithm\ContentEncryption\AESMCrypt;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\AESOpenSSL;

class AESEnginesTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param string $K
     * @param string $iv
     * @param string $plaintext
     * @param string $expected_cyphertext
     *
     * @dataProvider getTestVectors
     */
    public function testAES128($K, $iv, $plaintext, $expected_cyphertext)
    {
        $k = substr($K, strlen($K) / 2);

        $openssl_cyphertext = AESOpenSSL::encrypt($plaintext, $k, $iv);
        $mcrypt_cyphertext = AESMCrypt::encrypt($plaintext, $k, $iv);

        $this->assertEquals($expected_cyphertext, $openssl_cyphertext);
        $this->assertEquals($expected_cyphertext, $mcrypt_cyphertext);

        $this->assertEquals($plaintext, AESOpenSSL::decrypt($openssl_cyphertext, $k, $iv));
        $this->assertEquals($plaintext, AESMCrypt::decrypt($mcrypt_cyphertext, $k, $iv));
    }

    public function getTestVectors()
    {
        return [
            [
                $this->convertArrayToBinString([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]),
                $this->convertArrayToBinString([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]),
                $this->convertArrayToBinString([76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46]),
                $this->convertArrayToBinString([40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102]),
            ],
            [
                hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
                hex2bin('1af38c2dc2b96ffdd86694092341bc04'),
                hex2bin('41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365'),
                hex2bin('c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db'),
            ],
            [
                hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'),
                hex2bin('1af38c2dc2b96ffdd86694092341bc04'),
                hex2bin('41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365'),
                hex2bin('ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3'),
            ],
            [
                hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'),
                hex2bin('1af38c2dc2b96ffdd86694092341bc04'),
                hex2bin('41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365'),
                hex2bin('4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6'),
            ],
        ];
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
}
