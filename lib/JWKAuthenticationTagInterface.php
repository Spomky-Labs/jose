<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWK object used for content encryption to calculate and check an authentication tag
 */
interface JWKAuthenticationTagInterface
{
    /**
     */
    public function calculateAuthenticationTag($data);

    /**
     */
    public function checkAuthenticationTag($data);
}
