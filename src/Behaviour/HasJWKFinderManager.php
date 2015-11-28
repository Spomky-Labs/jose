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

use Jose\JWKFinderManagerInterface;

trait HasJWKFinderManager
{
    /**
     * @var \Jose\JWKFinderManagerInterface
     */
    private $jwk_finder_manager;

    /**
     * @param \Jose\JWKFinderManagerInterface $jwk_finder_manager
     */
    private function setJWKFinderManager(JWKFinderManagerInterface $jwk_finder_manager)
    {
        $this->jwk_finder_manager = $jwk_finder_manager;
    }

    /**
     * @return \Jose\JWKFinderManagerInterface
     */
    private function getJWKFinderManager()
    {
        return $this->jwk_finder_manager;
    }
}
