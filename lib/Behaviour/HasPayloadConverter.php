<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Behaviour;

use SpomkyLabs\Jose\Payload\PayloadConverterManagerInterface;

trait HasPayloadConverter
{
    /**
     * @var \SpomkyLabs\Jose\Payload\PayloadConverterManagerInterface
     */
    private $payload_converter;

    /**
     * @param \SpomkyLabs\Jose\Payload\PayloadConverterManagerInterface $payload_converter
     *
     * @return self
     */
    public function setPayloadConverter(PayloadConverterManagerInterface $payload_converter)
    {
        $this->payload_converter = $payload_converter;

        return $this;
    }

    /**
     * @return \SpomkyLabs\Jose\Payload\PayloadConverterManagerInterface
     */
    public function getPayloadConverter()
    {
        return $this->payload_converter;
    }
}
