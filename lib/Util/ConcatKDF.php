<?php

namespace SpomkyLabs\Jose\Util;

class ConcatKDF
{
    /**
     * @param string  $encryption_algorithm
     * @param integer $encryption_key_size
     */
    public static function generate($Z, $encryption_algorithm, $encryption_key_size, $apu = "", $apv = "")
    {
        $encryption_segments = array(
            self::toInt32Bits(1),                                                   // Round number 1
            $Z,                                                                     // Z (shared secret)
            self::toInt32Bits(strlen($encryption_algorithm)).$encryption_algorithm, // Size of algorithm and algorithm
            self::toInt32Bits(strlen($apu)).$apu,                                   // PartyUInfo
            self::toInt32Bits(strlen($apv)).$apv,                                   // PartyVInfo
            self::toInt32Bits($encryption_key_size),                                // SuppPubInfo (the encryption key size)
            "",                                                                     // SuppPrivInfo
        );

        return substr(hex2bin(hash('sha256', implode('', $encryption_segments))), 0, $encryption_key_size/8);
    }

    /**
     * @param integer $value
     */
    private static function toInt32Bits($value)
    {
        return hex2bin(str_pad(dechex($value), 8, "0", STR_PAD_LEFT));
    }
}
