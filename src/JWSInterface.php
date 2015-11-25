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

interface JWSInterface extends JWTInterface
{
    /**
     * Returns the signature associated with the loaded JWS.
     *
     * @return string
     */
    public function getSignature();

    /**
     * Set the signature associated with the loaded JWS.
     *
     * @param string $signature The signature
     *
     * @return self
     */
    public function setSignature($signature);
}
