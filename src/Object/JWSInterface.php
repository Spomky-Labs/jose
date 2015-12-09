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
     * @return string
     */
    public function getSignature();

    /**
     * Set the signature associated with the loaded JWS.
     * Note: This method is used internally and should not be used directly.
     *
     * @param string $signature The signature
     *
     * @return \Jose\Object\JWSInterface
     */
    public function withSignature($signature);
}
