<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Key Manager.
 */
interface JWKManagerInterface
{
    /**
     * Find keys usign the header
     * @param  array  $header   The header
     * @return JWKSetInterface  A set of keys
     */
    public function findByHeader(array $header);

    /**
     *
     */
    public function createJWK(array $values);

    /**
     *
     */
    public function createJWKSet(array $values = array());

    /**
     * Load a JWKSet from an url
     * @param  string $url          The URL where to find the JWKSet
     * @return JWKSetInterface|null Return a JWKSet object depending on the URL, or null if an error occured or the URL is invalid
     */
    public function loadFromUrl($url);

    /**
     * Return the type of key depending on the signature, key encryption or content encryption algorithm passed in argument
     * 
     * @param  string $value The algorithm
     * @return string        The type of key
     */
    public function getType($value);
}
