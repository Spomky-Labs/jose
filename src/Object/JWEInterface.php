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

interface JWEInterface extends JWTInterface
{
    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null The cyphertext
     */
    public function getCiphertext();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $ciphertext The cyphertext
     *
     * @return \Jose\Object\JWEInterface
     */
    public function withCiphertext($ciphertext);

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null The encrypted key
     */
    public function getEncryptedKey();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $encrypted_key The encrypted key
     *
     * @return \Jose\Object\JWEInterface
     */
    public function withEncryptedKey($encrypted_key);

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getAAD();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $aad
     *
     * @return \Jose\Object\JWEInterface
     */
    public function withAAD($aad);

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getIV();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $iv
     *
     * @return \Jose\Object\JWEInterface
     */
    public function withIV($iv);

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getTag();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $tag
     *
     * @return \Jose\Object\JWEInterface
     */
    public function withTag($tag);
}
