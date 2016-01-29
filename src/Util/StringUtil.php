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
    public static function strlen($string)
    {
        return function_exists('mb_strlen') ? mb_strlen($string, '8bit') : strlen($string);
    }

    public static function substr($string, $start, $length = null)
    {
        return function_exists('mb_substr') ? mb_substr($string, $start, $length, '8bit') : substr($string, $start, $length);
    }

    public static function str_pad($input, $pad_length, $pad_string = null, $pad_style = null)
    {
        return function_exists('mb_strlen') ? self::mb_pad_str($input, $pad_length, $pad_string, $pad_style) : str_pad($input, $pad_length, $pad_string, $pad_style);
    }

    private static function mb_pad_str($input, $pad_length, $pad_string = null, $pad_style = null)
    {
        return str_pad($input, strlen($input)-mb_strlen($input, '8bit')+$pad_length, $pad_string, $pad_style);
    }
}
