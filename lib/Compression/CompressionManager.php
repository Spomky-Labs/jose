<?php

namespace SpomkyLabs\JOSE\Compression;

use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManagerInterface;

/**
 * Compression algorithm manager.
 */
class CompressionManager implements CompressionManagerInterface
{
    protected $compression_algorithms = array();

    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[] = $compression_algorithm;

        return $this;
    }

    public function getCompressionAlgorithm($name)
    {
        foreach ($this->compression_algorithms as $algorithm) {
            if ($algorithm->isMethodSupported($name)) {
                return $algorithm;
            }
        }

        return;
    }
}
