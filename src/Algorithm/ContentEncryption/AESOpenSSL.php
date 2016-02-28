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
final class AESOpenSSL implements AESInterface
{
    /**
     * @param string $data
     * @param string $k
     * @param string $iv
     *
     * @return string
     */
    public static function encrypt($data, $k, $iv)
    {
        return openssl_encrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * @param string $data
     * @param string $k
     * @param string $iv
     *
     * @return string
     */
    public static function decrypt($data, $k, $iv)
    {
        return openssl_decrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * @param string $k
     *
     * @return string
     */
    private static function getMode($k)
    {
        return 'aes-'.(8 *  strlen($k)).'-cbc';
    }
}
