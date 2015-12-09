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
     * Set the protected header of the JWT.
     *
     * @param array $headers The protected headers parameters
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withProtectedHeaders(array $headers);

    /**
     * Returns the unprotected header of the JWT.
     *
     * @return array
     */
    public function getUnprotectedHeaders();

    /**
     * Set the unprotected header of the JWT.
     *
     * @param array $headers The unprotected headers parameters
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withUnprotectedHeaders(array $headers);

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
     * Set the value of the protected header of the specified key.
     *
     * @param string $key   The key
     * @param mixed  $value Header value
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withProtectedHeader($key, $value);

    /**
     * Unset the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withoutProtectedHeader($key);

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
     * Set the value of the unprotected header of the specified key.
     *
     * @param string $key   The key
     * @param mixed  $value Header value
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withUnprotectedHeader($key, $value);

    /**
     * Unset the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withoutUnprotectedHeader($key);

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
     * Set the payload of the JWT.
     *
     * @param mixed $payload Payload
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withPayload($payload);

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
     * @param string $key   The key
     * @param mixed  $value Claim value
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withClaim($key, $value);

    /**
     * @param string $key The key
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withoutClaim($key);

    /**
     * @param array $claims The claims
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withClaims(array $claims);

    /**
     * Returns the complete input.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getInput();

    /**
     * @param string $input
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withInput($input);

    /**
     * Returns the protected header encoded as represented in serialization.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string
     */
    public function getEncodedProtectedHeaders();

    /**
     * @param string $encoded_protected_header
     *                                         Note: This method is used internally and should not be used directly.
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withEncodedProtectedHeaders($encoded_protected_header);

    /**
     * Returns the payload encoded as represented in serialization.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string
     */
    public function getEncodedPayload();

    /**
     * @param string $encoded_payload
     *                                Note: This method is used internally and should not be used directly.
     *
     * @return \Jose\Object\JWTInterface
     */
    public function withEncodedPayload($encoded_payload);
}
