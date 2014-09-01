<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
abstract class GZip implements CompressionInterface
{
    abstract protected function getCompressionLevel();
    
    public function getMethod()
    {
        return 'GZ';
    }

    public function compress($data)
    {
        return gzencode($data, $this->getCompressionLevel());
    }

    public function uncompress($data)
    {
        return gzdecode($data);
    }
}
