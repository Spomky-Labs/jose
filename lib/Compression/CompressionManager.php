<?php

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
    protected $compression_algorithms = array();

    /**
     * @param  CompressionInterface $compression_algorithm
     * @return $this
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[$compression_algorithm->getMethodName()] = $compression_algorithm;

        return $this;
    }

    /**
     * @param  string                    $name
     * @return CompressionInterface|null
     */
    public function getCompressionAlgorithm($name)
    {
        return array_key_exists($name, $this->compression_algorithms) ? $this->compression_algorithms[$name] : null;
    }
}
