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

use Jose\JWTManagerInterface;

trait HasJWTManager
{
    /**
     * @var \Jose\JWTManagerInterface
     */
    private $jwt_manager;

    /**
     * @param \Jose\JWTManagerInterface $jwt_manager
     *
     * @return self
     */
    private function setJWTManager(JWTManagerInterface $jwt_manager)
    {
        $this->jwt_manager = $jwt_manager;

        return $this;
    }

    /**
     * @return \Jose\JWTManagerInterface
     */
    private function getJWTManager()
    {
        return $this->jwt_manager;
    }
}
