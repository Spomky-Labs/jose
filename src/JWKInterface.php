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

interface JWKInterface extends \JsonSerializable
{
    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function getValues();

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @return mixed|null The value
     */
    public function getValue($key);

    /**
     * Set values of the JWK object.
     *
     * @param string $key   Key
     * @param mixed  $value Value to store
     *
     * @return \Jose\JWKInterface
     */
    public function withValue($key, $value);

    /**
     * The key type.
     * This is an convenient method and must return the value `getValue('kty')`.
     *
     * @return string|null The key type
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.1
     */
    public function getKeyType();

    /**
     * The public key use.
     * This is an convenient method and must return the value `getValue('use')`.
     * Values defined by the specification are 'sign' or 'enc'.
     *
     * @return string|null The public key use
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.2
     */
    public function getPublicKeyUse();

    /**
     * The key operations.
     * This is an convenient method and must return the value `getValue('key_ops')`.
     * Values defined by the specification are 'sign', 'verify', 'decrypt', 'encrypt', 'wrapKey', 'unwrapKey', 'deriveKey' and 'deriveBits'.
     *
     * @return string|null The key operations
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.3
     */
    public function getKeyOperations();

    /**
     * The key algorithm.
     * This is an convenient method and must return the value `getValue('alg')`.
     * Values defined by the JWA specification.
     *
     * @return string|null The key algorithm
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.4
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37
     */
    public function getAlgorithm();

    /**
     * The key ID.
     * This is an convenient method and must return the value `getValue('kid')`.
     *
     * @return string|null The key ID
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.5
     */
    public function getKeyID();

    /**
     * The key X.509 URL.
     * This is an convenient method and must return the value `getValue('x5u')`.
     *
     * @return string|null The key X.509 URL
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.6
     */
    public function getX509Url();

    /**
     * The key X.509 Certificate Chain.
     * This is an convenient method and must return the value `getValue('x5c')`.
     *
     * @return string|null The key X.509 Certificate Chain
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.7
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#appendix-B
     */
    public function getX509CertificateChain();

    /**
     * The key X.509 Certificate Sha-1 Thumbprint.
     * This is an convenient method and must return the value `getValue('x5t')`.
     *
     * @return string|null The key X.509 Certificate Sha-1 Thumbprint
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.8
     */
    public function getX509CertificateSha1Thumbprint();

    /**
     * The key X.509 Certificate Sha-256 Thumbprint.
     * This is an convenient method and must return the value `getValue('x5t#256')`.
     *
     * @return string|null The key X.509 Certificate Sha-256 Thumbprint
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-key-37#section-4.9
     */
    public function getX509CertificateSha256Thumbprint();
}
