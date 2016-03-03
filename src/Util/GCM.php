<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Assert\Assertion;

final class GCM
{
    /**
     * @param string $K
     * @param string $IV
     * @param string $P
     * @param string $A
     *
     * @return array
     */
    public static function encrypt($K, $IV, $P, $A)
    {
        list($J0, $v, $a_len_padding, $H) = self::common($K, $IV, $A);

        $C = self::getGCTR($K, self::getInc(32, $J0), $P);
        $u = self::calcVector($C);
        $c_len_padding = self::addPadding($C);

        $S = self::getHash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
        $T = self::getMSB(128, self::getGCTR($K, $J0, $S));

        return [$C, $T];
    }

    /**
     * @param string $K
     * @param string $IV
     * @param string $C
     * @param string $A
     * @param string $T
     *
     * @return array
     */
    public static function decrypt($K, $IV, $C, $A, $T)
    {
        list($J0, $v, $a_len_padding, $H) = self::common($K, $IV, $A);

        $P = self::getGCTR($K, self::getInc(32, $J0), $C);

        $u = self::calcVector($C);
        $c_len_padding = self::addPadding($C);

        $S = self::getHash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
        $T1 = self::getMSB(self::getLength($T), self::getGCTR($K, $J0, $S));
        $result = strcmp($T, $T1);
        Assertion::eq($result, 0, 'Unable to decrypt or to verify the tag.');

        return $P;
    }

    private static function common($K, $IV, $A)
    {
        $key_length = strlen($K) * 8;
        Assertion::inArray($key_length, [128, 192, 256], 'Bad key length.');

        $H = openssl_encrypt(str_repeat("\0", 16), 'aes-'.(strlen($K)*8).'-ecb', $K, OPENSSL_NO_PADDING|OPENSSL_RAW_DATA); //---
        $iv_len = self::getLength($IV);

        if ($iv_len == 96) {
            $J0 = $IV.pack('H*', '00000001');
        } else {
            $s = self::calcVector($IV);
            Assertion::eq(($s + 64) % 8, 0, 'Unable to decrypt or to verify the tag.');

            $packed_iv_len = pack('N', $iv_len);
            $iv_len_padding = str_pad($packed_iv_len, 8, "\0", STR_PAD_LEFT);
            $hash_X = $IV.str_pad('', ($s + 64) / 8, "\0").$iv_len_padding;
            $J0 = self::getHash($H, $hash_X);
        }
        $v = self::calcVector($A);
        $a_len_padding = self::addPadding($A);

        return [$J0, $v, $a_len_padding, $H];
    }

    /**
     * @param string $value
     *
     * @return int
     */
    private static function calcVector($value)
    {
        return (128 * ceil(self::getLength($value) / 128)) - self::getLength($value);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function addPadding($value)
    {
        return str_pad(pack('N', self::getLength($value)), 8, "\0", STR_PAD_LEFT);
    }

    /**
     * @param string $x
     *
     * @return int
     */
    private static function getLength($x)
    {
        return strlen($x) * 8;
    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private static function getMSB($num_bits, $x)
    {
        $num_bytes = $num_bits / 8;

        return substr($x, 0, $num_bytes);
    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private static function getLSB($num_bits, $x)
    {
        $num_bytes = ($num_bits / 8);

        return substr($x, -$num_bytes);
    }

    /**
     * @param int $s_bits
     * @param int $x
     *
     * @return string
     */
    private static function getInc($s_bits, $x)
    {
        $lsb = self::getLSB($s_bits, $x);
        $X = self::toUInt32Bits($lsb) + 1;
        $res = self::getMSB(self::getLength($x) - $s_bits, $x).pack('N', $X);

        return $res;
    }

    /**
     * @param string $bin
     *
     * @return mixed
     */
    private static function toUInt32Bits($bin)
    {
        // $bin is the binary 32-bit BE string that represents the integer
        $int_size = 4;
        if ($int_size <= 4) {
            list(, $h, $l) = unpack('n*', $bin);

            return $l + ($h * 0x010000);
        } else {
            list(, $int) = unpack('N', $bin);

            return $int;
        }
    }

    /**
     * @param $X
     * @param $Y
     *
     * @return string
     */
    private static function getProduct($X, $Y)
    {
        $R = pack('H*', 'E1').str_pad('', 15, "\0");
        $Z = str_pad('', 16, "\0");
        $V = $Y;

        $parts = str_split($X, 4);
        $x = sprintf('%032b%032b%032b%032b', self::toUInt32Bits($parts[0]), self::toUInt32Bits($parts[1]), self::toUInt32Bits($parts[2]), self::toUInt32Bits($parts[3]));
        $lsb_mask = "\1";
        for ($i = 0; $i < 128; $i++) {
            if ($x[$i]) {
                $Z = self::getBitXor($Z, $V);
            }
            $lsb_8 = substr($V, -1);
            if (ord($lsb_8 & $lsb_mask)) {
                $V = self::getBitXor(self::shiftStringToRight($V), $R);
            } else {
                $V = self::shiftStringToRight($V);
            }
        }

        return $Z;
    }

    /**
     * @param string $input
     *
     * @return string
     */
    private static function shiftStringToRight($input)
    {
        $width = 4;
        $parts = array_map('self::toUInt32Bits', str_split($input, $width));
        $runs = count($parts);

        for ($i = $runs - 1; $i >= 0; $i--) {
            if ($i) {
                $lsb1 = $parts[$i - 1] & 0x00000001;
                if ($lsb1) {
                    $parts[$i] = ($parts[$i] >> 1) | 0x80000000;
                    $parts[$i] = pack('N', $parts[$i]);
                    continue;
                }
            }
            $parts[$i] = ($parts[$i] >> 1) & 0x7FFFFFFF; // get rid of sign bit
            $parts[$i] = pack('N', $parts[$i]);
        }
        $res = implode('', $parts);

        return $res;
    }

    /**
     * @param string $H
     * @param string $X
     *
     * @return mixed
     */
    private static function getHash($H, $X)
    {
        $Y = [];
        $Y[0] = str_pad('', 16, "\0");
        $num_blocks = (int) (strlen($X) / 16);
        for ($i = 1; $i <= $num_blocks; $i++) {
            $Y[$i] = self::getProduct(self::getBitXor($Y[$i - 1], substr($X, ($i - 1) * 16, 16)), $H);
        }

        return $Y[$num_blocks];
    }

    /**
     * @param string $K
     * @param string $ICB
     * @param string $X
     *
     * @return null|string
     */
    private static function getGCTR($K, $ICB, $X)
    {
        if ($X == '') {
            return '';
        }

        $n = (int) ceil(self::getLength($X) / 128);
        $CB = [];
        $Y = [];
        $CB[1] = $ICB;
        for ($i = 2; $i <= $n; $i++) {
            $CB[$i] = self::getInc(32, $CB[$i - 1]);
        }
        for ($i = 1; $i < $n; $i++) {
            $C = openssl_encrypt($CB[$i], 'aes-'.(strlen($K)*8).'-ecb', $K, OPENSSL_NO_PADDING|OPENSSL_RAW_DATA);
            $Y[$i] = self::getBitXor(substr($X, ($i - 1) * 16, 16), $C);
        }

        $Xn = substr($X, ($n - 1) * 16);
        $C = openssl_encrypt($CB[$n], 'aes-'.(strlen($K)*8).'-ecb', $K, OPENSSL_NO_PADDING|OPENSSL_RAW_DATA);
        $Y[$n] = self::getBitXor($Xn, self::getMSB(self::getLength($Xn), $C));

        return implode('', $Y);
    }

    /**
     * @param string $o1
     * @param string $o2
     *
     * @return string
     */
    private static function getBitXor($o1, $o2)
    {
        $xorWidth = PHP_INT_SIZE;
        $o1 = str_split($o1, $xorWidth);
        $o2 = str_split($o2, $xorWidth);
        $res = '';
        $runs = count($o1);
        for ($i = 0; $i < $runs; $i++) {
            $res .= $o1[$i] ^ $o2[$i];
        }

        return $res;
    }
}
