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

final class GCM
{
    /**
     * @param string $K
     * @param string $IV
     * @param string $P
     * @param string $A
     * @param int    $t
     *
     * @return array|null
     */
    public function gcm_encrypt($K, $IV, $P, $A, $t = 128) {

        $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        if(!$cipher)
            return null;
        $key_length = StringUtil::getStringLength($K) * 8;
        if($key_length != 128 && $key_length != 192 && $key_length != 256) {
            die("encryp invalid key length {$key_length}\n");
        }

        $iv_size = mcrypt_enc_get_iv_size($cipher);
        $iv = str_repeat(chr(0), 16);  // initialize to 16 byte string of "0"s
        $s = mcrypt_generic_init($cipher, $K, $iv);
        if( ($s < 0) || ($s === false)) {
            die("encryp mcrypt init error $s");
        }
        $H = mcrypt_generic($cipher, StringUtil::addPadding('', 16, "\0"));
        $iv_len = $this->gcm_len($IV);
        if($iv_len == 96) {
            $J0 = $IV . pack('H*', '00000001');
        } else {
            $s = (128 * ceil($iv_len / 128)) - $iv_len;
            if(($s + 64) % 8)
                die("gcm_encrypt s {$s} + 64 not byte size");
            $packed_iv_len = pack('N', $iv_len);
            $iv_len_padding = StringUtil::addPadding($packed_iv_len, 8, "\0", STR_PAD_LEFT);
            $hash_X = $IV . StringUtil::addPadding('', ($s + 64) / 8, "\0") . $iv_len_padding;
            $J0 = $this->gcm_hash($H, $hash_X);
        }
        $C = $this->gcm_gctr($K, $this->gcm_inc(32, $J0), $P);

        $u = (128 * ceil($this->gcm_len($C) / 128)) - $this->gcm_len($C);
        $v = (128 * ceil($this->gcm_len($A) / 128)) - $this->gcm_len($A);
        $a_len_padding = StringUtil::addPadding(pack('N', $this->gcm_len($A)), 8, "\0", STR_PAD_LEFT);
        $c_len_padding = StringUtil::addPadding(pack('N', $this->gcm_len($C)), 8, "\0", STR_PAD_LEFT);

        $S = $this->gcm_hash($H, $A . StringUtil::addPadding('', $v / 8, "\0") . $C . StringUtil::addPadding('', $u / 8, "\0") . $a_len_padding . $c_len_padding);
        $T = $this->gcm_MSB($t, $this->gcm_gctr($K, $J0, $S));
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);
        return array($C, $T);
    }

    /**
     * @param string $K
     * @param string $IV
     * @param string $C
     * @param string $A
     * @param string $T
     *
     * @return array|null
     */
    public function gcm_decrypt($K, $IV, $C, $A, $T) {

        $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        if(!$cipher)
            return NULL;
        $key_length = StringUtil::getStringLength($K) * 8;

        if($key_length != 128 && $key_length != 192 && $key_length != 256) {
            die("encryp invalid key length\n");
        }

        $iv_size = mcrypt_enc_get_iv_size($cipher);
        $iv = str_repeat(chr(0), 16);  // initialize to 16 byte string of "0"s
        $s = mcrypt_generic_init($cipher, $K, $iv);
        if( ($s < 0) || ($s === false)) {
            die("encryp mcrypt init error $s");
        }

        $H = mcrypt_generic($cipher, StringUtil::addPadding('', 16, "\0"));

        $iv_len = $this->gcm_len($IV);
        if($iv_len == 96) {
            $J0 = $IV . pack('H*', '00000001');
        } else {
            $s = (128 * ceil($iv_len / 128)) - $iv_len;
            if(($s + 64) % 8)
                die("gcm_encrypt s {$s} + 64 not byte size");
            $packed_iv_len = pack('N', $iv_len);
            $iv_len_padding = StringUtil::addPadding($packed_iv_len, 8, "\0", STR_PAD_LEFT);
            $hash_X = $IV . StringUtil::addPadding('', ($s + 64) / 8, "\0") . $iv_len_padding;
            $J0 = $this->gcm_hash($H, $hash_X);
        }
        $P = $this->gcm_gctr($K, $this->gcm_inc(32, $J0), $C);

        $u = (128 * ceil($this->gcm_len($C) / 128)) - $this->gcm_len($C);
        $v = (128 * ceil($this->gcm_len($A) / 128)) - $this->gcm_len($A);
        $a_len_padding = StringUtil::addPadding(pack('N', $this->gcm_len($A)), 8, "\0", STR_PAD_LEFT);
        $c_len_padding = StringUtil::addPadding(pack('N', $this->gcm_len($C)), 8, "\0", STR_PAD_LEFT);

        $S = $this->gcm_hash($H, $A . StringUtil::addPadding('', $v / 8, "\0") . $C . StringUtil::addPadding('', $u / 8, "\0") . $a_len_padding . $c_len_padding);
        $T1 = $this->gcm_MSB($this->gcm_len($T), $this->gcm_gctr($K, $J0, $S));
        $result = strcmp($T, $T1);
        if($result)
            return null;
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);
        return $P;
    }

    /**
     * @param string $x
     *
     * @return int
     */
    private function gcm_len($x)
    {
        return StringUtil::getStringLength($x) * 8;
    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private function gcm_MSB($num_bits, $x) {
        if(!$num_bits || !$x)
            die('gcm_MSB invalid params');
        if($num_bits % 8)
            die('gcm_MSB num_bits is not byte size');
        $num_bytes = $num_bits / 8;
        $len_x = StringUtil::getStringLength($x);
        if($num_bytes > StringUtil::getStringLength($x))
            die("gcm_MSB num_bits {$num_bits} bytes({$num_bytes}) > x {$len_x}");
        return substr($x, 0, $num_bytes);

    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private function gcm_LSB($num_bits, $x) {
        if(!$num_bits || !$x)
            die('gcm_LSB invalid params');
        if($num_bits % 8)
            die('gcm_LSB num_bits is not byte size');
        $num_bytes = ($num_bits / 8);
        if($num_bytes > StringUtil::getStringLength($x))
            die("gcm_LSB num_bits {$num_bits} > x {$x}");
        return substr($x, $num_bytes * -1);

    }

    /**
     * @param int $s_bits
     * @param int $x
     *
     * @return string
     */
    private function gcm_inc($s_bits, $x) {
        if(!$s_bits || $s_bits != 32)
            die("gcm_inc invalid s_bits");
        if(!$x)
            die("gcm_inc invalid x");
        if($s_bits % 8)
            die('gcm_inc s_bits is not byte size');
        $lsb = $this->gcm_LSB($s_bits, $x);
        $X = ($this->_uint32be($lsb) + 1);
        $res = $this->gcm_MSB($this->gcm_len($x) - $s_bits, $x) . pack('N', $X);
        return $res;
    }

    /**
     * @param string $bin
     *
     * @return mixed
     */
    private function _uint32be($bin)
    {
        // $bin is the binary 32-bit BE string that represents the integer
//     $int_size = PHP_INT_SIZE;
        $int_size = 4;
        if ($int_size <= 4){
            list(,$h,$l) = unpack('n*', $bin);
            return ($l + ($h*0x010000));
        }
        else{
            list(,$int) = unpack('N', $bin);
            return $int;
        }
    }

    /**
     * @param $X
     * @param $Y
     *
     * @return string
     */
    private function gcm_product($X, $Y) {
        $R = pack('H*', 'E1') . StringUtil::addPadding('', 15, "\0");
        $Z = StringUtil::addPadding('', 16, "\0");
        $V = $Y;
        if(StringUtil::getStringLength($X) != 16)
            die('Invalid length for X');
        $parts = str_split($X, 4);
        $x = sprintf("%032b%032b%032b%032b", $this->_uint32be($parts[0]), $this->_uint32be($parts[1]), $this->_uint32be($parts[2]), $this->_uint32be($parts[3]));
        $lsb_mask = "\1";
        for($i = 0; $i < 128; $i++) {
            if($x[$i])
                $Z = $this->bitxor($Z, $V);
            $lsb_8 = substr($V, -1);
            if(ord($lsb_8 & $lsb_mask))
                $V = $this->bitxor($this->str_right_shift($V), $R);
            else
                $V = $this->str_right_shift($V);
        }
        return $Z;
    }

    /**
     * @param string $input
     *
     * @return string
     */
    private function str_right_shift($input) {
//     $width = PHP_INT_SIZE; // doesn't work well on 64-bit systems
        $width = 4;
        $parts = array_map([$this, '_uint32be'], str_split($input, $width));
        $runs = count($parts);
        $len = StringUtil::getStringLength($input) / 4;
        if(!is_int($len))
            die('not int len');
        for($i=$runs - 1; $i >= 0; $i--) {
            if($i) {
                $lsb1 = $parts[$i - 1] & 0x00000001;
                if($lsb1) {
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
    private function gcm_hash($H, $X) {
        if(!$H or !$X)
            die("gcm_hash invalid params");
        if(StringUtil::getStringLength($X) % 16)
            die("gcm_hash X is not multiple of 16 bytes");
        $Y = array();
        $Y[0] = StringUtil::addPadding('', 16, "\0");
        $num_blocks = StringUtil::getStringLength($X) / 16;
        for($i = 1; $i <= $num_blocks; $i++) {
            $Y[$i] = $this->gcm_product($this->bitxor($Y[$i - 1], substr($X, ($i - 1) * 16, 16)), $H);
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
    private function gcm_gctr($K, $ICB, $X) {
        if($X == '')
            return '';

        $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        if(!$cipher)
            return NULL;
        $key_length = StringUtil::getStringLength($K) * 8;

        if($key_length != 128 && $key_length != 192 && $key_length != 256) {
            die("gcm_gctr invalid key length\n");
        }

        $iv_size = mcrypt_enc_get_iv_size($cipher);
        $iv = str_repeat(chr(0), 16);  // initialize to 16 byte string of "0"s
        $s = mcrypt_generic_init($cipher, $K, $iv);
        if( ($s < 0) || ($s === false)) {
            die("gcm_gctr mcrypt init error $s");
        }

        $n = ceil($this->gcm_len($X) / 128);
        $CB = array();
        $Y = array();
        $CB[1] = $ICB;
        for($i = 2; $i <= $n; $i++) {
            $CB[$i] = $this->gcm_inc(32, $CB[$i - 1]);
        }
        for($i = 1; $i < $n; $i++) {
            $C = mcrypt_generic($cipher, $CB[$i]);
            $Y[$i] = $this->bitxor(substr($X, ($i - 1) * 16, 16), $C);
        }

        $Xn = substr($X, ($n - 1) * 16);
        $C = mcrypt_generic($cipher, $CB[$n]);
        $Y[$n] = $this->bitxor($Xn, $this->gcm_MSB($this->gcm_len($Xn), $C));
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);
        return implode('', $Y);
    }

    /**
     * @param string $o1
     * @param string $o2
     *
     * @return string
     */
    private function bitxor($o1, $o2) {
        $xorWidth = PHP_INT_SIZE;
        $o1 = str_split($o1, $xorWidth);
        $o2 = str_split($o2, $xorWidth);
        $res = '';
        $runs = count($o1);
        for($i=0;$i<$runs;$i++)
            $res .= $o1[$i] ^ $o2[$i];
        return $res;
    }
}
