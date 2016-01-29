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

use Jose\Encrypter;

final class EncrypterFactory
{
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
