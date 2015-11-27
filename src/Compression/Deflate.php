<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Compression;

/**
 * This class implements the compression algorithm DEF (defalte)
 * This compression algorithm is part of the specification.
 */
final class Deflate implements CompressionInterface
{
    /**
     * @var int
     */
    protected $compression_level = -1;

    /**
     * Deflate constructor.
     *
     * @param int $compression_level
     */
    public function __construct($compression_level = -1)
    {
        if (!is_integer($compression_level) || $compression_level < -1 || $compression_level > 9) {
            throw new \InvalidArgumentException('The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        }

        $this->compression_level = $compression_level;
    }

    /**
     * @return int
     */
    private function getCompressionLevel()
    {
        return $this->compression_level;
    }

    /**
     * {@inheritdoc}
     */
    public function getMethodName()
    {
        return 'DEF';
    }

    /**
     * {@inheritdoc}
     */
    public function compress($data)
    {
        $data = gzdeflate($data, $this->getCompressionLevel());
        if (false === $data) {
            throw new \RuntimeException('Unable to compress data');
        }
        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function uncompress($data)
    {
        $data = gzinflate($data);
        if (false === $data) {
            throw new \RuntimeException('Unable to uncompress data');
        }
        return $data;
    }
}
