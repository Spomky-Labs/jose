<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\CompressionManagerInterface;
use SpomkyLabs\JOSE\Compression\Deflate;
use SpomkyLabs\JOSE\Compression\ZLib;
use SpomkyLabs\JOSE\Compression\GZip;

/**
 * Class representing a JSON Web Signature.
 */
class CompressionManager implements CompressionManagerInterface
{
    public function getCompressionMethod($name)
    {
        switch ($name) {
            case 'deflate':
                return new Deflate();
            case 'zlib':
                return new ZLib();
            case 'gzip':
                return new GZip();
            default:
                return null;
        }
    }
}
