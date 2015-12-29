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

use Jose\Payload\PayloadConverterManager;

final class PayloadConverterFactory
{
    /**
     * @param \Jose\Payload\PayloadConverterInterface[] $payload_converters
     *
     * @return \Jose\Payload\PayloadConverterManagerInterface
     */
    public static function createPayloadConverter(array $payload_converters = [])
    {
        $payload_converter_manager = new PayloadConverterManager();

        foreach ($payload_converters as $payload_converter) {
            $payload_converter_manager->addConverter($payload_converter);
        }

        return $payload_converter_manager;
    }
}
