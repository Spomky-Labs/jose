<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to sign data
 */
interface JWKSignInterface
{
    /**
     * Sign data
     *
     * @return string
     */
    public function sign($data);
}
