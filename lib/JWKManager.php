<?php

namespace SpomkyLabs\JOSE;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    public function findJWKSetByHeader(array $header)
    {
        $key_set = $this->createJWKSet();
        foreach ($this->getSupportedMethods() as $key => $method) {
            if (isset($header[$key])) {
                $result = $this->$method($header[$key]);
                if (null !== $result) {
                    $key_set->addKey($result);
                }
            }
        }

        return $key_set;
    }

    protected function getSupportedMethods()
    {
        return array(
            'kid' => 'findJWKByKid',
            'jwk' => 'findJWKByJWK'
        );
    }

    abstract protected function findJWKByKid($kid);

    protected function findJWKByJWK(array $values)
    {
        return $this->createJWK($values);
    }
}
