<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use SpomkyLabs\Jose\JWT;
use SpomkyLabs\Jose\JWS;
use SpomkyLabs\Jose\JWE;
use Jose\JWTManagerInterface;

/**
 * Class representing a JSON Web Signature.
 */
class JWTManager implements JWTManagerInterface
{
    /**
     * @return \Jose\JWTInterface
     */
    public function createJWT()
    {
        return new JWT();
    }

    /**
     * @return \Jose\JWSInterface
     */
    public function createJWS()
    {
        return new JWS();
    }

    /**
     * @return \Jose\JWEInterface
     */
    public function createJWE()
    {
        return new JWE();
    }
}
