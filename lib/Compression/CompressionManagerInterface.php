<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Compression;

use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManagerInterface as Base;

interface CompressionManagerInterface extends Base
{
    /**
     * @param CompressionInterface $compression_algorithm
     *
     * @return self
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm);
}
