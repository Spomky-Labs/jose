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

interface JWSInterface extends JWTInterface
{
    /**
     * Returns the signature associated with the loaded JWS.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getSignature();

    /**
     * Returns the encoded payload associated with the loaded JWS.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getEncodedPayload();

    /**
     * Returns the encoded protected header associated with the loaded JWS.
     * Note: This method is used internally and should not be used directly.
     *
     * @return string|null
     */
    public function getEncodedProtectedHeader();
}
