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

use Jose\Decrypter;

final class DecrypterFactory
{
    /**
     * DecrypterFactory constructor.
     *
     * This factory is not supposed to be instantiated
     */
    private function __construct()
    {
    }

    /**
     * @param string[]                         $algorithms
     * @param string[]                         $compression_methods
     * @param \Jose\Checker\CheckerInterface[] $checker_managers
     *
     * @return \Jose\DecrypterInterface
     */
    public static function createDecrypter(array $algorithms, array $compression_methods = ['DEF'], array $checker_managers = [])
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $compression_manager = CompressionManagerFactory::createCompressionManager($compression_methods);
        $checker_manager = CheckerManagerFactory::createCheckerManager($checker_managers);

        return new Decrypter($algorithm_manager, $compression_manager, $checker_manager);
    }
}
