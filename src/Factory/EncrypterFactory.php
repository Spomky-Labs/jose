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

use Jose\Encrypter;

final class EncrypterFactory
{
    /**
     * EncrypterFactory constructor.
     *
     * This factory is not supposed to be instantiated
     */
    private function __construct() {}

    /**
     * @param string[] $algorithms
     * @param string[] $compression_methods
     *
     * @return \Jose\EncrypterInterface
     */
    public static function createEncrypter(array $algorithms, array $compression_methods = ['DEF'])
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $compression_manager = CompressionManagerFactory::createCompressionManager($compression_methods);

        return new Encrypter($algorithm_manager, $compression_manager);
    }
}
