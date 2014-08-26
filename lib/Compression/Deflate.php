<?php

namespace SpomkyLabs\JOSE\Compression;

use SpomkyLabs\JOSE\CompressionInterface;

/**
 * This interface is used by all compression methods
 */
class Deflate implements CompressionInterface
{
    public function getMethod()
    {
        return 'deflate';
    }

    public function compress($data)
    {
        return gzdeflate($data);
    }

    public function uncompress($data)
    {
        return gzinflate($data);
    }
}
