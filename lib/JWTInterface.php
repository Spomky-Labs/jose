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
    public function setPayload($payload);

    /**
     * Returns the payload of the JWT.
     *
     * @return mixed|null
     */
    public function getPayload();

    /**
     * Returns the header of the JWT.
     *
     * @return array
     */
    public function getHeader();

    /**
     * @return mixed
     */
    public function getHeaderValue($key);

    /**
     * Set the header of the JWT.
     *
     * @return self
     */
    public function setHeader(array $header);
}
