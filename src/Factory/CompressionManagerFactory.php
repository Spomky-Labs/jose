<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManager;

final class CompressionManagerFactory
{
    /**
     * @param array $methods
     *
     * @return \Jose\Compression\CompressionManagerInterface
     */
    public static function createCompressionManager(array $methods)
    {
        $compression_manager = new CompressionManager();

        foreach ($methods as $key => $value) {
            if ($value instanceof CompressionInterface) {
                $compression_manager->addCompressionAlgorithm($value);
            } elseif (is_string($value)) {
                $class = self::getMethodClass($value);
                $compression_manager->addCompressionAlgorithm(new $class());
            } else {
                $class = self::getMethodClass($key);
                $compression_manager->addCompressionAlgorithm(new $class($value));
            }
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
        Assertion::true(self::isAlgorithmSupported($method), sprintf('Compression method "%s" is not supported.', $method));

        return self::getSupportedMethods()[$method];
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
