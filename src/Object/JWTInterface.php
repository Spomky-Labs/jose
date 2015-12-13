<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWTInterface
{
    /**
     * Returns the protected header of the JWT.
     *
     * @return array
     */
    public function getProtectedHeaders();

    /**
     * Returns the unprotected header of the JWT.
     *
     * @return array
     */
    public function getUnprotectedHeaders();

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasProtectedHeader($key);

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getUnprotectedHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasUnprotectedHeader($key);

    /**
     * Returns the value of the headers (protected or unprotected).
     *     *.
     *
     * @return array Header values
     */
    public function getHeaders();

    /**
     * Returns the value of the header (protected or unprotected) of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeader($key);

    /**
     * Returns the value of the header (protected or unprotected) or the payload of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-5.3
     */
    public function getHeaderOrClaim($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeaderOrClaim($key);

    /**
     * Returns the payload of the JWT.
     *
     * @return string                       Payload
     * @return array                        Payload
     * @return \Jose\Object\JWKInterface    Payload
     * @return \Jose\Object\JWKSetInterface Payload
     * @return mixed                        Payload
     */
    public function getPayload();

    /**
     * Returns the value of the payload of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Payload value
     */
    public function getClaim($key);

    /**
     * Returns the claims.
     *
     * @return mixed|null Payload value
     */
    public function getClaims();

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasClaim($key);

    /**
     * @return bool
     */
    public function hasClaims();

    /**
     * Returns the complete input.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getInput();
}
