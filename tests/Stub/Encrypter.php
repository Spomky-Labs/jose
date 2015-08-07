<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use Jose\JWAManagerInterface;
use Jose\JWTManagerInterface;
use Jose\JWKManagerInterface;
use Jose\JWKSetManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use SpomkyLabs\Jose\Encrypter as Base;
use SpomkyLabs\Jose\Payload\JWKConverter;
use SpomkyLabs\Jose\Payload\JWKSetConverter;
use SpomkyLabs\Jose\Payload\PayloadConverterManager;
use SpomkyLabs\Jose\Payload\PrimitiveConverter;

/**
 * Class representing a JSON Web Signature.
 */
class Encrypter extends Base
{
    protected $jwa_manager;
    protected $jwt_manager;
    protected $jwk_manager;
    protected $jwkset_manager;
    protected $compression_manager;
    protected $payload_converter_manager;

    /**
     * {@inheritdoc}
     */
    protected function getPayloadConverter()
    {
        if (is_null($this->payload_converter_manager)) {
            $this->payload_converter_manager = new PayloadConverterManager();
            $this->payload_converter_manager->addConverter(new JWKConverter($this->getJWKManager()))
                                            ->addConverter(new JWKSetConverter($this->getJWKSetManager()));
        }

        return $this->payload_converter_manager;
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWTManager()
    {
        return $this->jwt_manager;
    }

    public function setJWTManager(JWTManagerInterface $jwt_manager)
    {
        $this->jwt_manager = $jwt_manager;

        return $this;
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
    protected function getJWKSetManager()
    {
        return $this->jwkset_manager;
    }

    public function setJWKSetManager(JWKSetManagerInterface $jwkset_manager)
    {
        $this->jwkset_manager = $jwkset_manager;

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
     * @param int $length
     *
     * @return string
     */
    private function generateRandomString($length)
    {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }elseif (function_exists('mcrypt_create_iv')) {
            return mcrypt_create_iv($length);
        }elseif (function_exists('openssl_random_pseudo_bytes')) {
            return openssl_random_pseudo_bytes($length);
        } elseif (class_exists('\phpseclib\Crypt\Random')) {
            return \phpseclib\Crypt\Random::string($length);
        } else {
            throw new \Exception('Unable to create a random string');
        }
    }
}
