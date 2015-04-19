<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;

/**
 * Trait used to convert payload.
 */
trait PayloadConverter
{
    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    abstract protected function getJWKSetManager();

    /**
     * @return \Jose\JWTManagerInterface
     */
    abstract protected function getJWTManager();

    /**
     * @param array $header
     * @param $payload
     *
     * @throws \Exception
     */
    protected function convertJWTContent(array $header, &$payload)
    {
        //The payload is a JWKSet or JWK object
        if (array_key_exists('cty', $header)) {
            switch ($header['cty']) {
                case 'jwk+json':
                    $payload = $this->getJWKManager()->createJWK(json_decode($payload, true));

                    return;
                case 'jwkset+json':
                    $values = json_decode($payload, true);
                    if (!array_key_exists('keys', $values)) {
                        throw new \Exception('Not a valid key set');
                    }
                    $payload = $this->getJWKSetManager()->createJWKSet($values['keys']);

                    return;
                default:
                    break;
            }
        }

        //The payload is a JSON array
        $json = json_decode($payload, true);
        if (is_array($json)) {
            $payload = $json;

            return;
        }
    }

    /**
     * @param $input
     */
    protected function checkInput(&$input)
    {
        if ($input instanceof JWKInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                ->setProtectedHeaderValue('cty', 'jwk+json');
            $input = $jwt;

            return;
        }
        if ($input instanceof JWKSetInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                ->setProtectedHeaderValue('cty', 'jwkset+json');
            $input = $jwt;

            return;
        }
        if (is_array($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input));
            $input = $jwt;

            return;
        }
        if (is_string($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload($input);
            $input = $jwt;

            return;
        }
        if (!$input instanceof JWTInterface) {
            throw new \InvalidArgumentException('Unsupported input type.');
        }
    }
}
