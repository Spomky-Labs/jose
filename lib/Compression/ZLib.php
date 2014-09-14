<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
abstract class ZLib implements CompressionInterface
{
    protected function getCompressionLevel()
    {
        return -1;
    }

    public function getMethod()
    {
        return 'ZLIB';
    }

    public function compress($data)
    {
        return gzcompress($data, $this->getCompressionLevel());
    }

    public function uncompress($data)
    {
        return gzuncompress($data);
    }
}
