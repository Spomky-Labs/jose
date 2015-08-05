<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 */
interface AESInterface
{
    /**
     * @param string $data
     * @param string $k
     * @param string $iv
     *
     * @return string
     */
    public static function encrypt($data, $k, $iv);

    /**
     * @param string $data
     * @param string $k
     * @param string $iv
     *
     * @return string
     */
    public static function decrypt($data, $k, $iv);
}
