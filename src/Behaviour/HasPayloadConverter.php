<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Payload\PayloadConverterManagerInterface;

trait HasPayloadConverter
{
    /**
     * @var \Jose\Payload\PayloadConverterManagerInterface
     */
    private $payload_converter;

    /**
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter
     */
    private function setPayloadConverter(PayloadConverterManagerInterface $payload_converter)
    {
        $this->payload_converter = $payload_converter;
    }

    /**
     * @return \Jose\Payload\PayloadConverterManagerInterface
     */
    private function getPayloadConverter()
    {
        return $this->payload_converter;
    }
}
