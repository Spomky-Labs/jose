<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKManagerInterface;
use SpomkyLabs\JOSE\JWTManager as Base;

/**
 * Class representing a JSON Web Signature.
 */
class JWTManager extends Base
{
    private $jwk_manager;

    public function getKeyManager()
    {
        return $this->jwk_manager;
    }

    public function getCompressionManager()
    {
        return new CompressionManager();
    }

    public function setKeyManager(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;

        return $this;
    }
}
