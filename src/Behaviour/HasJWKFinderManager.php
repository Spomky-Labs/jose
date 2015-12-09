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

use Jose\Finder\JWKFinderManagerInterface;

trait HasJWKFinderManager
{
    /**
     * @var \Jose\Finder\JWKFinderManagerInterface
     */
    private $jwk_finder_manager;

    /**
     * @param \Jose\Finder\JWKFinderManagerInterface $jwk_finder_manager
     */
    private function setJWKFinderManager(JWKFinderManagerInterface $jwk_finder_manager)
    {
        $this->jwk_finder_manager = $jwk_finder_manager;
    }

    /**
     * @return \Jose\Finder\JWKFinderManagerInterface
     */
    private function getJWKFinderManager()
    {
        return $this->jwk_finder_manager;
    }
}
