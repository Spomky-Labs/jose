<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to decrypt data
 */
interface JWKDecryptInterface
{
    /**
     * Decrypt data
     *
     * @return mixed|null
     */
    public function decrypt($data);
}
