<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\CompressionManagerInterface;
use SpomkyLabs\JOSE\Tests\Compression\Deflate;
use SpomkyLabs\JOSE\Tests\Compression\ZLib;
use SpomkyLabs\JOSE\Tests\Compression\GZip;

/**
 * Class representing a JSON Web Signature.
 */
class CompressionManager implements CompressionManagerInterface
{
    public function getCompressionMethod($name)
    {
        switch ($name) {
            case 'DEF':
                return new Deflate();
            case 'ZLIB':
                return new ZLib();
            case 'GZ':
                return new GZip();
            default:
                return null;
        }
    }
}
