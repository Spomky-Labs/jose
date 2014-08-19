<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to verify the signature of data
 */
interface JWKVerifyInterface
{
    /**
     * Verify the signature of data
     *
     * @return boolean
     */
    public function verify($data, $signature);
}
