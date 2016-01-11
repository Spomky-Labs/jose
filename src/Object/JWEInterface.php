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
     * @return string|null The encrypted key
     */
    public function getEncryptedKey();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getAAD();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getIV();

    /**
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getTag();

    /**
     * Returns the encoded protected header associated with the loaded JWE.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getEncodedProtectedHeader();
}
