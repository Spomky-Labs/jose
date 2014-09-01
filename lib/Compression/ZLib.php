<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
abstract class ZLib implements CompressionInterface
{
    abstract protected function getCompressionLevel();

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
