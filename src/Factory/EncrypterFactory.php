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
     * @param string[]                                  $algorithms
     * @param \Jose\Payload\PayloadConverterInterface[] $payload_converters
     * @param string[]                                  $compression_methods
     *
     * @return \Jose\EncrypterInterface
     */
    public static function createEncrypter(array $algorithms, array $payload_converters = [], array $compression_methods = ['DEF'])
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $payload_converter_manager = PayloadConverterFactory::createPayloadConverter($payload_converters);
        $compression_manager = CompressionManagerFactory::createCompressionManager($compression_methods);

        return new Encrypter($algorithm_manager, $payload_converter_manager, $compression_manager);
    }
}
