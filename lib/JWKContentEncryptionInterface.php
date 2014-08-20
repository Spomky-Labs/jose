<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWK object used for content encryption to create a CEK and an IV
 */
interface JWKContentEncryptionInterface
{
    /**
     * @return Encryption\AES
     */
    public function createCEK();

    /**
     * @return Encryption\AES
     */
    public function createIV();
}
