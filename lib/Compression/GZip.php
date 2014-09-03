<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
class GZip implements CompressionInterface
{
    protected function getCompressionLevel()
    {
        return -1;
    }

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
