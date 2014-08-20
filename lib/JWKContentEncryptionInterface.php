<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWK object used for content encryption to create a CEK and an IV
 */
interface JWKContentEncryptionInterface
{
    /**
     */
    public function createCEK();

    /**
     */
    public function createIV();
}
