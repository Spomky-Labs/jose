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
        }
        throw new \RuntimeException('Unable to create random bytes.');
    }
}
