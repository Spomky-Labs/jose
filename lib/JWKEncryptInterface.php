<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to encrypt data
 */
interface JWKEncryptInterface
{
    /**
     * Encrypt data
     * 
     * @return string
     */
    public function encrypt($data);
}
