<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

/**
 * Class String
 */
final class StringUtil
{
    private function __construct() {}

    public static function strlen($string)
    {
        return function_exists('mb_strlen') ? mb_strlen($string, '8bit') : strlen($string);
    }

    public static function substr($string, $start, $length = null)
    {
        return function_exists('mb_substr') ? mb_substr($string, $start, $length, '8bit') : substr($string, $start, $length);
    }
}
