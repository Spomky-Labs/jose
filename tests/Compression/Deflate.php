<?php

namespace SpomkyLabs\JOSE\Tests\Compression;

use SpomkyLabs\JOSE\Compression\Deflate as Base;

class Deflate extends Base
{
    protected function getCompressionLevel()
    {
        return 9;
    }
}
