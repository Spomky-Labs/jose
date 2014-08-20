<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Key Manager.
 */
interface JWKManagerInterface
{
    /**
     *
     */
    public function findJWKByHeader(array $header);

    /**
     *
     */
    public function createJWK(array $values);

    /**
     *
     */
    public function createJWKSet(array $values = array());
}
