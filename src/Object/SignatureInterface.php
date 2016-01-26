<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Signature Instruction Interface.
 *
 * This interface is required by the SignerInterface to signed payloads and create a JWS.
 */
interface SignatureInterface
{
    /**
     * The protected header associated with the signature.
     *
     * @internal
     *
     * @return null|string
     */
    public function getEncodedProtectedHeaders();

    /**
     * Set the encoded protected headers associated with the signature.
     *
     * @internal
     *
     * @param string $encoded_protected_headers
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withEncodedProtectedHeaders($encoded_protected_headers);

    /**
     * The protected header associated with the signature.
     *
     * @return array
     */
    public function getProtectedHeaders();

    /**
     * Set the protected headers associated with the signature.
     *
     * @param array $protected_headers
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withProtectedHeaders(array $protected_headers);

    /**
     * Set the protected header.
     *
     * @param string     $key
     * @param mixed|null $value
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withProtectedHeader($key, $value);

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
     * The unprotected header associated with the signature.
     *
     * @return array
     */
    public function getHeaders();

    /**
     * Set the headers associated with the signature.
     *
     * @param array $headers
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withHeaders(array $headers);

    /**
     * Set the header.
     *
     * @param string     $key
     * @param mixed|null $value
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withHeader($key, $value);

    /**
     * Returns the value of the unprotected header of the specified key.
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
     * The protected and unprotected header associated with the signature.
     *
     * @return array
     */
    public function getAllHeaders();

    /**
     * Returns the value of the signature.
     *
     * @return string
     */
    public function getSignature();

    /**
     * @param string $values
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function withSignature($values);
}
