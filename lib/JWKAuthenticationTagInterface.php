<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface must be implemented with a JWK object used for content encryption to calculate and check an authentication tag
 */
interface JWKAuthenticationTagInterface
{
    /**
     * @return string
     */
    public function calculateAuthenticationTag($data);

    /**
     * @return boolean
     */
    public function checkAuthenticationTag($data);
}
