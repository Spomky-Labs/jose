<?php

namespace SpomkyLabs\JOSE;

interface JWKSetInterface
{
    /**
     * @return array
     */
    public function toPrivate();

    /**
     * @return array
     */
    public function toPublic();

    /**
     * Returns the Compression Algorithm of the JWE.
     *
     * @return JWKInterface[] An array of keys stored in the key set
     */
    public function getKeys();

    /**
     * Add a key in the key set
     * @param JWKInterface $key The key to add
     */
    public function addKey(JWKInterface $key);

    /**
     *
     */
    public function isEmpty();
}
