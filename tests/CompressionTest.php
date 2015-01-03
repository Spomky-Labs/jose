<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Compression\CompressionManager;
use SpomkyLabs\JOSE\Compression\Deflate;
use SpomkyLabs\JOSE\Compression\GZip;
use SpomkyLabs\JOSE\Compression\ZLib;

class CompressionTest extends \PHPUnit_Framework_TestCase
{
    public function testGetValidCompressionAlgorithm()
    {
        $manager = new CompressionManager();
        $manager->addCompressionAlgorithm(new Deflate())
                ->addCompressionAlgorithm(new GZip())
                ->addCompressionAlgorithm(new ZLib());

        $compression = $manager->getCompressionAlgorithm("DEF");
        $this->assertInstanceOf("Jose\Compression\CompressionInterface", $compression);
    }

    public function testGetInvalidCompressionAlgorithm()
    {
        $manager = new CompressionManager();
        $manager->addCompressionAlgorithm(new Deflate())
                ->addCompressionAlgorithm(new GZip())
                ->addCompressionAlgorithm(new ZLib());

        $compression = $manager->getCompressionAlgorithm("FOO");
        $this->assertNull($compression);
    }

    public function testDeflate()
    {
        $compression = new Deflate();
        $compression->setCompressionLevel(9);

        $data        = "Please compress this little string";
        $compressed   = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    public function testGZip()
    {
        $compression = new GZip();
        $compression->setCompressionLevel(9);

        $data        = "Please compress this little string";
        $compressed   = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    public function testZLib()
    {
        $compression = new ZLib();
        $compression->setCompressionLevel(9);

        $data        = "Please compress this little string";
        $compressed   = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testDeflateInvalidCompressionLevel()
    {
        $compression = new Deflate();
        $compression->setCompressionLevel(100);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testGZipInvalidCompressionLevel()
    {
        $compression = new GZip();
        $compression->setCompressionLevel(100);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testZLibInvalidCompressionLevel()
    {
        $compression = new ZLib();
        $compression->setCompressionLevel(100);
    }
}
