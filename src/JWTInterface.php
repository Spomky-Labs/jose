<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

interface JWTInterface
{
    /**
     * Returns the complete input.
     *
     * @return string|null
     */
    public function getInput();

    /**
     * @param string $input
     *
     * @return \Jose\JWTInterface
     */
    public function withInput($input);

    /**
     * Returns the protected header encoded as represented in serialization.
     *
     * @return string
     */
    public function getEncodedProtectedHeader();

    /**
     * @param string $encoded_protected_header
     *
     * @return \Jose\JWTInterface
     */
    public function withEncodedProtectedHeader($encoded_protected_header);

    /**
     * Returns the protected header of the JWT.
     *
     * @return array
     */
    public function getProtectedHeader();

    /**
     * Set the protected header of the JWT.
     *
     * @param array $headers The protected headers parameters
     *
     * @return \Jose\JWTInterface
     */
    public function withProtectedHeader(array $headers);

    /**
     * Returns the unprotected header of the JWT.
     *
     * @return array
     */
    public function getUnprotectedHeader();

    /**
     * Set the unprotected header of the JWT.
     *
     * @param array $headers The unprotected headers parameters
     *
     * @return \Jose\JWTInterface
     */
    public function withUnprotectedHeader(array $headers);

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeaderValue($key);

    /**
     * Set the value of the protected header of the specified key.
     *
     * @param string $key   The key
     * @param mixed  $value Header value
     *
     * @return \Jose\JWTInterface
     */
    public function withProtectedHeaderValue($key, $value);

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getUnprotectedHeaderValue($key);

    /**
     * Set the value of the unprotected header of the specified key.
     *
     * @param string $key   The key
     * @param mixed  $value Header value
     *
     * @return \Jose\JWTInterface
     */
    public function withUnprotectedHeaderValue($key, $value);

    /**
     * Returns the value of the header (protected or unprotected) of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeaderValue($key);

    /**
     * Returns the value of the header (protected or unprotected) or the payload of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-5.3
     */
    public function getHeaderOrPayloadValue($key);

    /**
     * Returns the payload of the JWT.
     *
     * @return string                Payload
     * @return array                 Payload
     * @return \Jose\JWKInterface    Payload
     * @return \Jose\JWKSetInterface Payload
     * @return mixed                 Payload
     */
    public function getPayload();

    /**
     * Set the payload of the JWT.
     *
     * @param mixed $payload Payload
     *
     * @return \Jose\JWTInterface
     */
    public function withPayload($payload);

    /**
     * Returns the payload encoded as represented in serialization.
     *
     * @return string
     */
    public function getEncodedPayload();

    /**
     * @param string $encoded_payload
     *
     * @return \Jose\JWTInterface
     */
    public function withEncodedPayload($encoded_payload);

    /**
     * Returns the value of the payload of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Payload value
     */
    public function getPayloadValue($key);

    /**
     * The type.
     * This is an convenient method and must return the payload value `getHeaderValue('typ')`.
     *
     * @return string|null The type
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-5.1
     */
    public function getType();

    /**
     * The content type.
     * This is an convenient method and must return the payload value `getHeaderValue('cty')`.
     *
     * @return string|null The content type
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-5.2
     */
    public function getContentType();

    /**
     * The issuer.
     * This is an convenient method and must return the payload value `getPayloadValue('iss')`.
     *
     * @return string|null The issuer
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.1
     */
    public function getIssuer();

    /**
     * The subject.
     * This is an convenient method and must return the payload value `getPayloadValue('sub')`.
     *
     * @return string|null The subject
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.2
     */
    public function getSubject();

    /**
     * The audience.
     * This is an convenient method and must return the payload value `getPayloadValue('aud')`.
     *
     * @return string|null The audience
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.3
     */
    public function getAudience();

    /**
     * The expiration time on or after which the JWT MUST NOT be accepted for processing.
     * This is an convenient method and must return the payload value `getPayloadValue('exp')`.
     *
     * @return string|null The expiration time on or after which the JWT MUST NOT be accepted for processing
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.4
     */
    public function getExpirationTime();

    /**
     * The time before which the JWT MUST NOT be accepted for processing.
     * This is an convenient method and must return the payload value `getPayloadValue('nbf')`.
     *
     * @return string|null The time before which the JWT MUST NOT be accepted for processing
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.5
     */
    public function getNotBefore();

    /**
     * The time at which the JWT was issued.
     * This is an convenient method and must return the payload value `getPayloadValue('iat')`.
     *
     * @return string|null The time at which the JWT was issued
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.6
     */
    public function getIssuedAt();

    /**
     * The unique identifier for the JWT.
     * This is an convenient method and must return the payload value `getPayloadValue('jti')`.
     *
     * @return string|null The unique identifier for the JWT
     *
     * @see https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.7
     */
    public function getJWTID();

    /**
     * The key algorithm.
     * This is an convenient method and must return the value `getHeaderValue('alg')`.
     * Values defined by the JWA specification.
     *
     * @return string|null The key algorithm
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.1
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.1
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37
     */
    public function getAlgorithm();

    /**
     * The JWK Url.
     * This is an convenient method and must return the value `getHeaderValue('jku')`.
     *
     * @return string|null The JWK Url
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.2
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.4
     */
    public function getJWKUrl();

    /**
     * The JWK.
     * This is an convenient method and must return the value `getHeaderValue('jwk')`.
     *
     * @return JWKInterface|array|null The JWK
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.3
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.5
     */
    public function getJWK();

    /**
     * The key ID.
     * This is an convenient method and must return the value `getHeaderValue('kid')`.
     *
     * @return string|null The key ID
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.4
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.6
     */
    public function getKeyID();

    /**
     * The key X.509 URL.
     * This is an convenient method and must return the value `getHeaderValue('x5u')`.
     *
     * @return string|null The key X.509 URL
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.5
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.7
     */
    public function getX509Url();

    /**
     * The key X.509 Certificate Chain.
     * This is an convenient method and must return the value `getHeaderValue('x5c')`.
     *
     * @return string|null The key X.509 Certificate Chain
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.6
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.8
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#appendix-B
     */
    public function getX509CertificateChain();

    /**
     * The key X.509 Certificate Sha-1 Thumbprint.
     * This is an convenient method and must return the value `getHeaderValue('x5t')`.
     *
     * @return string|null The key X.509 Certificate Sha-1 Thumbprint
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.7
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.9
     */
    public function getX509CertificateSha1Thumbprint();

    /**
     * The key X.509 Certificate Sha-256 Thumbprint.
     * This is an convenient method and must return the value `getHeaderValue('x5t#256')`.
     *
     * @return string|null The key X.509 Certificate Sha-256 Thumbprint
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.8
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.10
     */
    public function getX509CertificateSha256Thumbprint();

    /**
     * The critical parameters.
     * This is an convenient method and must return the value `getHeaderValue('crit')`.
     *
     * @return string[]|null The critical parameters
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-4.1.9
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.13
     */
    public function getCritical();
}
