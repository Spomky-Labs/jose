<?php

namespace SpomkyLabs\JOSE;

use Jose\JWKInterface;
use Jose\JWKSetInterface;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    abstract protected function getSupportedMethods();

    public function findByHeader(array $header)
    {
        $keys = $this->createJWKSet();
        foreach ($this->getSupportedMethods() as $method) {
            $result = $this->$method($header);
            if ($result instanceof JWKInterface) {
                $keys->addKey($result);
            } elseif ($result instanceof JWKSetInterface) {
                foreach ($result->getKeys() as $key) {
                    $keys->addKey($key);
                }
            }
        }

        return $keys;
    }

    public function getType($value)
    {
        switch ($value) {
            case 'ES256':
            case 'ES384':
            case 'ES512':
            case 'ECDH-ES':
                return 'EC';
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
            case 'RSA1_5':
            case 'RSA-OAEP':
            case 'RSA-OAEP-256':
                return 'RSA';
            case 'none':
                return 'none';
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return 'oct';
            case 'A128CBC-HS256':
            case 'A192CBC-HS384':
            case 'A256CBC-HS512':
                return 'AES';
            case 'dir':
                return 'dir';
            default:
                throw new \Exception("Unsupported algorithm '$value'");
        }
    }
}
