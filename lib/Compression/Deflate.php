<?php

namespace SpomkyLabs\Jose\Compression;

use Jose\Compression\CompressionInterface;

/**
 * This class implements the compression algorithm DEF (defalte)
 * This compression algorithm is part of the specification.
 */
class Deflate implements CompressionInterface
{
    /**
     * @var int
     */
    protected $compression_level = -1;

    /**
     * @param int $level
     */
    public function setCompressionLevel($level)
    {
        if (!is_numeric($level) || $level < -1 || $level > 9) {
            throw new \InvalidArgumentException('The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        }

        return $this;
    }

    /**
     * @return int
     */
    public function getCompressionLevel()
    {
        return $this->compression_level;
    }

    /**
     * @return string
     */
    public function getMethodName()
    {
        return 'DEF';
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function compress($data)
    {
        return gzdeflate($data, $this->getCompressionLevel());
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function uncompress($data)
    {
        return gzinflate($data);
    }
}
