<?php

namespace SpomkyLabs\JOSE\Tests\Compression;

use SpomkyLabs\JOSE\Compression\GZip as Base;

class GZip extends Base
{
    protected function getCompressionLevel()
    {
        return 9;
    }
}
