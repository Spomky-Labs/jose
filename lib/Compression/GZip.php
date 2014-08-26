<?php

namespace SpomkyLabs\JOSE\Compression;

use SpomkyLabs\JOSE\CompressionInterface;

/**
 * This interface is used by all compression methods
 */
class GZip implements CompressionInterface
{
    public function getMethod()
    {
        return 'gzip';
    }

    public function compress($data)
    {
        return gzencode($data);
    }

    public function uncompress($data)
    {
        return gzdecode($data);
    }
}
