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

interface JWEInterface extends JWTInterface
{
    /**
     * The key encryption algorithm.
     * This is an convenient method and must return the value `getHeaderValue('enc')`.
     *
     * @return string|null The key encryption algorithm
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.2
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37
     */
    public function getEncryptionAlgorithm();

    /**
     * The compression method.
     * This is an convenient method and must return the value `getHeaderValue('zip')`.
     *
     * @return string|null The compression method
     *
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37#section-4.1.3
     */
    public function getZip();

    /**
     * @return string|null The cyphertext
     */
    public function getCiphertext();

    /**
     * @param string $ciphertext The cyphertext
     *
     * @return \Jose\JWEInterface
     */
    public function withCiphertext($ciphertext);

    /**
     * @return string|null The encrypted key
     */
    public function getEncryptedKey();

    /**
     * @param string $encrypted_key The encrypted key
     *
     * @return \Jose\JWEInterface
     */
    public function withEncryptedKey($encrypted_key);

    /**
     * @return string|null
     */
    public function getAAD();

    /**
     * @param string $aad
     *
     * @return \Jose\JWEInterface
     */
    public function withAAD($aad);

    /**
     * @return string|null
     */
    public function getIV();

    /**
     * @param string $iv
     *
     * @return \Jose\JWEInterface
     */
    public function withIV($iv);

    /**
     * @return string|null
     */
    public function getTag();

    /**
     * @param string $tag
     *
     * @return \Jose\JWEInterface
     */
    public function withTag($tag);
}
