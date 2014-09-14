<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
class Deflate implements CompressionInterface
{
    protected function getCompressionLevel()
    {
        return -1;
    }

    public function getMethod()
    {
        return 'DEF';
    }

    public function compress($data)
    {
        return gzdeflate($data, $this->getCompressionLevel());
    }

    public function uncompress($data)
    {
        return gzinflate($data);
    }
}
