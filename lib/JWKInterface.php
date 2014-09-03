<?php

namespace SpomkyLabs\JOSE;

interface JWKInterface
{
    /**
     * Return the representation of the key as described in the JWK Draft 31
     *
     * @see IETF JWK Draft 31, Appendix A.1
     * @return string
     */
    public function __toString();

    /**
     * Returns an array that represents the values of the public key
     *
     * @return array
     */
    public function toPublic();

    /**
     * Get all values stored in the JWK object
     *
     * @return array Values of the JWK object
     */
    public function getValues();

    /**
     * Set a value in the JWK object.
     *
     * @param string $key   The key
     * @param mixed  $value The value
     */
    public function setValue($key, $value);

    /**
     * Get the value with a specific key
     *
     * @param  string $key The key
     * @return string The value
     */
    public function getValue($key);

    /**
     * @return boolean Return true if the key is private, else false
     */
    public function isPrivate();

    /**
     * @return boolean Return true if the key is public, else false
     */
    public function isPublic();
}
