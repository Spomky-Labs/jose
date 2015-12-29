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

use Jose\Loader;

final class LoaderFactory
{
    /**
     * @param \Jose\Payload\PayloadConverterInterface[] $payload_converters
     *
     * @return \Jose\LoaderInterface
     */
    public static function createLoader(array $payload_converters = [])
    {
        $payload_converter_manager = PayloadConverterFactory::createPayloadConverter($payload_converters);

        return new Loader($payload_converter_manager);
    }
}
