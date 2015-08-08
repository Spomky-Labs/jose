<?php

namespace SpomkyLabs\Test\Stub;

use Jose\JWKManagerInterface;
use Jose\JWAManagerInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWTManagerInterface;
use SpomkyLabs\Jose\Payload\JWKConverter;
use SpomkyLabs\Jose\Payload\JWKSetConverter;
use SpomkyLabs\Jose\Payload\PayloadConverterManager;
use SpomkyLabs\Jose\Signer as Base;

/**
 * Class representing a JSON Web Signature.
 */
class Signer extends Base
{
    protected $jwt_manager;
    protected $jwa_manager;
    protected $jwk_manager;
    protected $jwkset_manager;
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
}
