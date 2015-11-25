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

/**
 * Interface representing a JSON Web Token Manager.
 */
interface JWTManagerInterface
{
    /**
     * Create an empty JWT object.
     *
     * @return \Jose\JWTInterface
     */
    public function createJWT();

    /**
     * Create an empty JWS object.
     *
     * @return \Jose\JWSInterface
     */
    public function createJWS();

    /**
     * Create an empty JWE object.
     *
     * @return \Jose\JWEInterface
     */
    public function createJWE();
}
