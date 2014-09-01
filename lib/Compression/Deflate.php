<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
abstract class Deflate implements CompressionInterface
{
    abstract protected function getCompressionLevel();
    
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
