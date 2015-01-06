<?php

namespace SpomkyLabs\JOSE;

use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWKManagerInterface;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    abstract protected function getSupportedMethods();

    public function findByHeader(array $header)
    {
        $keys = $this->createJWKSet();
        foreach ($this->getSupportedMethods() as $method) {
            if (method_exists($this, $method)) {
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
}
