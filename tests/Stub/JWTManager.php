<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use Jose\JWKManagerInterface;
use Jose\JWAManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use SpomkyLabs\JOSE\JWTManager as Base;

/**
 * Class representing a JSON Web Signature.
 */
class JWTManager extends Base
{
    private $jwk_manager;
    private $jwa_manager;
    private $compression_manager = null;

    /**
     * {@inheritdoc}
     */
    protected function getAlgorithmManager()
    {
        return $this->jwa_manager;
    }

    public function setAlgorithmManager(JWAManagerInterface $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeyManager()
    {
        return $this->jwk_manager;
    }

    public function setKeyManager(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getCompressionManager()
    {
        return $this->compression_manager;
    }

    public function setCompressionManager(CompressionManagerInterface $compression_manager)
    {
        $this->compression_manager = $compression_manager;

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
