<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

use Jose\Util\StringUtil;

/**
 */
final class AESMCrypt implements AESInterface
{
    public static function encrypt($data, $k, $iv)
    {
        $resource = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $padded_text = self::pad($data, 16);
        mcrypt_generic_init($resource, $k, $iv);
        $cipherText = mcrypt_generic($resource, $padded_text);
        mcrypt_generic_deinit($resource);

        return $cipherText;
    }

    public static function decrypt($data, $k, $iv)
    {
        $resource = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($resource, $k, $iv);
        $decrypted = mdecrypt_generic($resource, $data);
        mcrypt_generic_deinit($resource);
        $decrypted_text = self::unpad($decrypted);

        return $decrypted_text;
    }

    private static function pad($data, $block_size)
    {
        $padding = $block_size - (strlen($data) % $block_size);
        $pattern = chr($padding);

        return $data.str_repeat($pattern, $padding);
    }

    private static function unpad($data)
    {
        $padChar = substr($data, -1);
        $padLength = ord($padChar);

        return substr($data, 0, -$padLength);
    }
}
