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
        $this->compression_algorithms[] = $compression_algorithm;

        return $this;
    }

    /**
     * @param  string $name
     * @return mixed
     */
    public function getCompressionAlgorithm($name)
    {
        foreach ($this->compression_algorithms as $algorithm) {
            if ($algorithm->isMethodSupported($name)) {
                return $algorithm;
            }
        }
    }
}
