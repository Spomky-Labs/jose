<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\Compression\CompressionManager;

final class CompressionManagerFactory
{
    /**
     * @param string[] $methods
     *
     * @return \Jose\Compression\CompressionManagerInterface
     */
    public static function createCompressionManager(array $methods)
    {
        $compression_manager = new CompressionManager();

        foreach ($methods as $method => $compression_level) {
            if (is_string($compression_level)) {
                $method = $compression_level;
                $compression_level = -1;
            }
            $class = self::getMethodClass($method);
            $compression_manager->addCompressionAlgorithm(new $class($compression_level));
        }

        return $compression_manager;
    }

    /**
     * @param string $method
     *
     * @return bool
     */
    private static function isAlgorithmSupported($method)
    {
        return array_key_exists($method, self::getSupportedMethods());
    }

    /**
     * @param string $method
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getMethodClass($method)
    {
        if (self::isAlgorithmSupported($method)) {
            return self::getSupportedMethods()[$method];
        }
        throw new \InvalidArgumentException(sprintf('Compression method "%s" is not supported.', $method));
    }

    private static function getSupportedMethods()
    {
        return [
            'DEF'  => '\Jose\Compression\Deflate',
            'GZ'   => '\Jose\Compression\GZip',
            'ZLIB' => '\Jose\Compression\ZLib',
        ];
    }
}
