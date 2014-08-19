<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Token.
 */
interface JWTInterface
{
    /**
     * Set the payload of the JWT.
     * 
     * @return self
     */
    public function setPayload(array $payload);
    
    /**
     * Returns the payload of the JWT.
     * 
     * @return array
     */
    public function getPayload();

    /**
     * Returns the header of the JWT.
     * 
     * @return array
     */
    public function getHeader();

    /**
     * Set the header of the JWT.
     *
     * @return self
     */
    public function setHeader(array $header);

    /**
     * @return boolean
     */
    public function isExpired();
}
