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
 * Interface representing a JSON Web Key Set Manager.
 */
interface JWKSetManagerInterface
{
    /**
     * Create a JWKSet object.
     *
     * @param array $values The values to set.
     *
     * @return \Jose\JWKSetInterface Returns a JWKSetInterface object
     */
    public function createJWKSet(array $values = []);
}
