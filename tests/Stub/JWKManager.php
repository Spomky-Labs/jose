<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKManager as Base;
use SpomkyLabs\JOSE\Tests\Stub\JWKSet;

/**
 */
class JWKManager extends Base
{
    private $keys = array();

    protected function findJWKByKid($kid)
    {
        return isset($this->keys[$kid])?$this->keys[$kid]:null;
    }

    public function createJWKSet()
    {
        return new JWKSet;
    }

    public function createJWK(array $values)
    {
        $class = $this->getClass($values['alg']);
        $jwk = new $class;
        $jwk->setValues($values);
        return $jwk;
    }

    private function getClass($alg)
    {
        switch ($alg) {
            case 'ES256':
            case 'ES384':
            case 'ES512':
                return 'SpomkyLabs\JOSE\Tests\Signature\ECDSA';
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return 'SpomkyLabs\JOSE\Tests\Signature\RSA';
            case 'none':
                return 'SpomkyLabs\JOSE\Tests\Signature\None';
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return 'SpomkyLabs\JOSE\Tests\Signature\Hmac';
            default:
                throw new \Exception("Unsupported algorithm $alg");
        }
    }
}
