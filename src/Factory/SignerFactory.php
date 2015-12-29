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

use Jose\Signer;

final class SignerFactory
{
    /**
     * @param string[]                                  $algorithms
     * @param \Jose\Payload\PayloadConverterInterface[] $payload_converters
     *
     * @return \Jose\SignerInterface
     */
    public static function createSigner(array $algorithms, array $payload_converters = [])
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $payload_converter_manager = PayloadConverterFactory::createPayloadConverter($payload_converters);

        return new Signer($algorithm_manager, $payload_converter_manager);
    }
}
