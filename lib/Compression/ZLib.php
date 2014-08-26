<?php

namespace SpomkyLabs\JOSE\Compression;

use SpomkyLabs\JOSE\CompressionInterface;

/**
 * This interface is used by all compression methods
 */
class ZLib implements CompressionInterface
{
    public function getMethod()
    {
        return 'zlib';
    }

    public function compress($data)
    {
        return gzcompress($data);
    }

    public function uncompress($data)
    {
        return gzuncompress($data);
    }
}
