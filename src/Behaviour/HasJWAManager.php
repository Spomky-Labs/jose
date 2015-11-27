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

use Jose\JWAManagerInterface;

trait HasJWAManager
{
    /**
     * @var \Jose\JWAManagerInterface
     */
    private $jwa_manager;

    /**
     * @param \Jose\JWAManagerInterface $jwa_manager
     */
    private function setJWAManager(JWAManagerInterface $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;
    }

    /**
     * @return \Jose\JWAManagerInterface
     */
    private function getJWAManager()
    {
        return $this->jwa_manager;
    }
}
