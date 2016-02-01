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

/**
 * Class String.
 */
final class StringUtil
{
    /**
     * @param int $size
     * 
     * @return string
     */
    public static function generateRandomBytes($size)
    {
        if (function_exists('random_bytes')) {
            return random_bytes($size);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return openssl_random_pseudo_bytes($size);
        } elseif (function_exists('mcrypt_create_iv')) {
            return mcrypt_create_iv($size);
        }
        throw new \RuntimeException('Unable to create random bytes.');
    }
    
    /**
     * @param string $string
     * 
     * @return int
     */
    public static function getStringLength($string)
    {
        return function_exists('mb_strlen') ? mb_strlen($string, '8bit') : strlen($string);
    }

    /**
     * @param string   $string
     * @param int      $start
     * @param null|int $length
     *
     * @return string
     */
    public static function getSubString($string, $start, $length = null)
    {
        return function_exists('mb_substr') ? mb_substr($string, $start, $length, '8bit') : substr($string, $start, $length);
    }

    /**
     * @param string      $input
     * @param int         $pad_length
     * @param null|string $pad_string
     * @param null|int    $pad_style
     *
     * @return string
     */
    public static function addPadding($input, $pad_length, $pad_string = null, $pad_style = null)
    {
        return function_exists('mb_strlen') ? self::addPaddingMultiBytes($input, $pad_length, $pad_string, $pad_style) : str_pad($input, $pad_length, $pad_string, $pad_style);
    }

    /**
     * @param string      $input
     * @param int         $pad_length
     * @param null|string $pad_string
     * @param null|int    $pad_style
     *
     * @return string
     */
    private static function addPaddingMultiBytes($input, $pad_length, $pad_string = null, $pad_style = null)
    {
        return str_pad($input, strlen($input) - mb_strlen($input, '8bit') + $pad_length, $pad_string, $pad_style);
    }
}
