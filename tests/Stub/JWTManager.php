<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKManagerInterface;
use SpomkyLabs\JOSE\JWTManager as Base;
use SpomkyLabs\JOSE\Compression\CompressionManager;
use SpomkyLabs\JOSE\Compression\Deflate;
use SpomkyLabs\JOSE\Compression\GZip;
use SpomkyLabs\JOSE\Compression\ZLib;

/**
 * Class representing a JSON Web Signature.
 */
class JWTManager extends Base
{
    private $jwk_manager;
    private $compression_manager = null;

    public function getKeyManager()
    {
        return $this->jwk_manager;
    }

    public function getCompressionManager()
    {
        if (null === $this->compression_manager) {
            $this->compression_manager = new CompressionManager();
            $this->compression_manager->addCompressionAlgorithm(new Deflate())
                                      ->addCompressionAlgorithm(new GZip())
                                      ->addCompressionAlgorithm(new ZLib());
        }

        return $this->compression_manager;
    }

    public function setKeyManager(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;

        return $this;
    }

    protected function createCEK($size)
    {
        return $this->generateRandomString($size / 8);
    }

    protected function createIV($size)
    {
        return $this->generateRandomString($size / 8);
    }

    /**
     * @param integer $length
     */
    private function generateRandomString($length)
    {
        return crypt_random_string($length);
    }
}
