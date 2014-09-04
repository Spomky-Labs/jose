<?php

namespace SpomkyLabs\JOSE\Algorithm;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to sign data
 */
interface SignatureInterface
{
    /**
     * Sign data
     * @param string $input  The input
     * @param array  $header The header
     *
     * @return string
     */
    public function sign($input, array $header = array());
}
