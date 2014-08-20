<?php

namespace SpomkyLabs\JOSE;

interface JWKSetInterface
{
    /**
     * Return the representation of the key set as described in the JWK Draft 31
     *
     * @see IETF JWK Draft 31, Appendix A.1
     * @return string
     */
    public function __toString();

    /**
     * Returns all keys in the key set.
     *
     * @return JWKInterface[] An array of keys stored in the key set
     */
    public function getKeys();

    /**
     * Add a key in the key set
     * @param JWKInterface $key The key to add
     * @return JWKSet
     */
    public function addKey(JWKInterface $key);

    /**
     * @return boolean Return true if the key set is empty, else false
     */
    public function isEmpty();
}
