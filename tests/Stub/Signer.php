<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use Jose\JWKManagerInterface;
use Jose\JWAManagerInterface;
use Jose\JWTManagerInterface;
use SpomkyLabs\Jose\Signer as Base;

/**
 * Class representing a JSON Web Signature.
 */
class Signer extends Base
{
    protected $jwt_manager;
    protected $jwk_manager;
    protected $jwa_manager;

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
}
