<?php

namespace SpomkyLabs\JOSE;

/**
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
