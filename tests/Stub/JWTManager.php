<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use Jose\JWKManagerInterface;
use Jose\JWAManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use SpomkyLabs\Jose\JWT;
use SpomkyLabs\Jose\JWS;
use SpomkyLabs\Jose\JWE;
use SpomkyLabs\Jose\JWTManager as Base;

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
    public function createJWT()
    {
        return new JWT();
    }

    /**
     * {@inheritdoc}
     */
    public function createJWS()
    {
        return new JWS();
    }

    /**
     * {@inheritdoc}
     */
    public function createJWE()
    {
        return new JWE();
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWAManager()
    {
        return $this->jwa_manager;
    }

    public function setJWAManager(JWAManagerInterface $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWKManager()
    {
        return $this->jwk_manager;
    }

    public function setJWKManager(JWKManagerInterface $jwk_manager)
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
