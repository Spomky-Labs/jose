<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Key Manager.
 */
interface JWKManagerInterface
{
    /**
     * Find keys using the header
     * 
     * @param  array           $header The header
     * @return JWKSetInterface A set of keys
     */
    public function findByHeader(array $header);

    /**
     * Create a JWK object using the values
     *
     * @param  array        $values The values of the key. Must at least contain 'kty' parameter
     * @return JWKInterface A JWK object
     */
    public function createJWK(array $values);

    /**
     * Create a JWKSet object to store JWK objects.
     *
     * @param  array           $values An array that contains keys
     * @return JWKSetInterface A JWKSet object
     */
    public function createJWKSet(array $values = array());

    /**
     * Return the type of key depending on the signature, key encryption or content encryption algorithm passed in argument
     *
     * @param  string $value The algorithm
     * @return string The type of key
     */
    public function getType($value);
}
