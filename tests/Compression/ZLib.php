<?php

namespace SpomkyLabs\JOSE\Tests\Compression;

use SpomkyLabs\JOSE\Compression\ZLib as Base;

class ZLib extends Base
{
    protected function getCompressionLevel()
    {
        return 9;
    }
}
