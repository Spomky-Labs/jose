<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\JWTInterface;

/**
 * Interface representing a JSON Web Key Manager.
 */
interface JWKManagerInterface
{
    /**
     *
     */
    public function findJWKSetByHeader(array $header);

    /**
     *
     */
    public function createJWK(array $values);

    /**
     *
     */
    public function createJWKSet();
}
