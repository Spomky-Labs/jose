<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 */
class AESOpenSSL implements AESInterface
{
    public static function encrypt($data, $k, $iv)
    {
        return openssl_encrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    public static function decrypt($data, $k, $iv)
    {
        return openssl_decrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    private static function getMode($k)
    {
        return 'aes-'.(8 * self::getLengthSafe($k)).'-cbc';
    }

    private static function getLengthSafe($str)
    {
        if (function_exists('mb_strlen')) {
            $length = mb_strlen($str, '8bit');
            if ($length === false) {
                throw new \Exception('Invalid encoding for mb_strlen()');
            }

            return $length;
        } else {
            return strlen($str);
        }
    }
}
