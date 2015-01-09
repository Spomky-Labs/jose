<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWKManagerInterface;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    protected function getSupportedMethods()
    {
        return array(
            'findByJWK',
        );
    }

    public function findByHeader(array $header)
    {
        $keys = $this->createJWKSet();

        // If the algorithm is none, we can return directly the key.
        if (array_key_exists("alg", $header) && "none" === $header["alg"]) {
            $jwk = $this->createJWK(array("kty"=>"none"));
            $keys->addKey($jwk);
            return $keys;
        }
        foreach ($this->getSupportedMethods() as $method) {
            if (!method_exists($this, $method)) {
                throw new \RuntimeException("The method '$method' does not exist.");
            }
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

    protected function findByJWK($header)
    {
        if (!isset($header['jwk'])) {
            return;
        }

        $jwk = $this->createJWK($header['jwk']);

        return $jwk;
    }
}
