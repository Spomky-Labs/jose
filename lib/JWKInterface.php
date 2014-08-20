<?php

namespace SpomkyLabs\JOSE;

interface JWKInterface
{
    /**
     * Returns a strin that represent the key
     *
     * @return string
     */
    public function __toString();

    /**
     * Returns an array that represent the values of the public key
     *
     * @return array
     */
    public function toPublic();

    /**
     * Set the values of the JWK object
     * @param array $values A list of values usable by the JWK object
     */
    public function setValues(array $values);

    /**
     * Get all values stored in the JWK object
     *
     * @return array Values of the JWK object
     */
    public function getValues();

    /**
     */
    public function setValue($key, $value);

    /**
     * Get the value with a specific key
     *
     * @param  string $key The key
     * @return string
     */
    public function getValue($key);

    /**
     * @return boolean Return true if the key is private, else false
     */
    public function isPrivate();
}
