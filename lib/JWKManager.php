<?php

namespace SpomkyLabs\JOSE;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    public function loadFromUrl($url)
    {
        $content = json_decode(file_get_contents($url), true);
        if(!is_array($content)) {
            return null;
        }
        if(!isset($content['keys'])) {
            return null;
        }
        return $this->createJWKSet($content['keys']);
    }

    public function findByHeader(array $header)
    {
        $keys = $this->createJWKSet();
        foreach ($this->getSupportedMethods() as $key => $method) {
            if (isset($header[$key])) {
                $result = $this->$method($header[$key]);
                if ($result instanceof JWKInterface) {
                    $keys->addKey($result);
                } elseif ($result instanceof JWKSetInterface) {
                    foreach ($result->getKeys() as $jwk) {
                        $keys->addKey($jwk);
                    }
                }
            }
        }
        return $keys;
    }

    protected function getSupportedMethods()
    {
        return array(
            'kid' => 'findJWKByKid',
            'jwk' => 'findJWKByJWK',
            'jku' => 'findJWKByUrl'
        );
    }

    abstract protected function findJWKByKid($kid);

    protected function findJWKByJWK(array $values)
    {
        return $this->createJWK($values);
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
                return 'None';
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return 'HMAC';
            case 'A128CBC-HS256':
            case 'A192CBC-HS384':
            case 'A256CBC-HS512':
                return 'AES';
            case 'dir':
                return 'Dir';
            default:
                throw new \Exception("Unsupported algorithm '$value'");
        }
    }
}
