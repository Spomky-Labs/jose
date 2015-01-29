<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWKManagerInterface;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    /**
     * @return array
     */
    protected function getSupportedMethods()
    {
        return array(
            'findByJWK',
        );
    }

    /**
     * @param  array           $header
     * @return JWKSetInterface
     */
    public function findByHeader(array $header)
    {
        $keys = $this->createJWKSet();

        // If the algorithm is none, we can return directly the key.
        if ($this->isUnsecuredSiganture($header)) {
            return $this->getNoneKeySet();
        }

        foreach ($this->getSupportedMethods() as $method) {
            if (!method_exists($this, $method)) {
                throw new \RuntimeException("The method '$method' does not exist.");
            }
            $result = $this->$method($header);
            $this->analyzeResult($keys, $result);
        }

        return $keys;
    }

    /**
     * @param $keys
     * @param $result
     */
    protected function analyzeResult(&$keys, $result)
    {
        if ($result instanceof JWKInterface) {
            $keys->addKey($result);
        } elseif ($result instanceof JWKSetInterface) {
            foreach ($result->getKeys() as $key) {
                $keys->addKey($key);
            }
        }
    }

    /**
     * @return JWKSetInterface
     */
    protected function getNoneKeySet()
    {
        $keys = $this->createJWKSet();
        $jwk = $this->createJWK(array("kty" => "none"));
        $keys->addKey($jwk);

        return $keys;
    }

    /**
     * @param  array $header
     * @return bool
     */
    protected function isUnsecuredSiganture(array $header)
    {
        return array_key_exists("alg", $header) && "none" === $header["alg"];
    }

    /**
     * @param $header
     * @return JWKInterface|void
     */
    protected function findByJWK($header)
    {
        if (!isset($header['jwk'])) {
            return;
        }

        $jwk = $this->createJWK($header['jwk']);

        return $jwk;
    }
}
