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
use Psr\Log\LoggerInterface;

final class DecrypterFactory
{
    /**
     * @param string[]                      $algorithms
     * @param string[]                      $compression_methods
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\DecrypterInterface
     */
    public static function createDecrypter(array $algorithms, array $compression_methods = ['DEF'], LoggerInterface $logger = null)
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $compression_manager = CompressionManagerFactory::createCompressionManager($compression_methods);

        return new Decrypter($algorithm_manager, $compression_manager, $logger);
    }
}
