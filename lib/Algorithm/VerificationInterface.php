<?php

namespace SpomkyLabs\JOSE\Algorithm;

/**
 * This interface must be implemented with a JWKInterface object to indicate that the key has capabilities to verify the signature of data
 */
interface VerificationInterface
{
    /**
     * Verify the signature of data
     * 
     * @param  string $input     The input
     * @param  string $signature The signature to verify
     * @param  array  $header    The header
     *
     * @return boolean
     */
    public function verify($input, $signature, array $header = array());
}
