<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\JWKManager;

trait HasJWKManager
{
    /**
     * @return \Jose\JWKManagerInterface
     */
    private function getJWKManager()
    {
        return new JWKManager();
    }
}
