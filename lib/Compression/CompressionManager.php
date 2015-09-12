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
use Jose\Compression\CompressionManagerInterface;

/**
 * Compression algorithm manager.
 */
class CompressionManager implements CompressionManagerInterface
{
    /**
     * @var array
     */
    protected $compression_algorithms = [];

    /**
     * @param CompressionInterface $compression_algorithm
     *
     * @return self
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[$compression_algorithm->getMethodName()] = $compression_algorithm;

        return $this;
    }

    /**
     * @param string $name
     *
     * @return CompressionInterface|null
     */
    public function getCompressionAlgorithm($name)
    {
        return array_key_exists($name, $this->compression_algorithms) ? $this->compression_algorithms[$name] : null;
    }
}
