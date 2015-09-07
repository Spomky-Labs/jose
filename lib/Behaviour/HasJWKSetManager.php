<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Behaviour;

use Jose\JWKSetManagerInterface;

trait HasJWKSetManager
{
    /**
     * @var \Jose\JWKSetManagerInterface
     */
    private $jwkset_manager;

    /**
     * @param \Jose\JWKSetManagerInterface $jwkset_manager
     *
     * @return self
     */
    public function setJWKSetManager(JWKSetManagerInterface $jwkset_manager)
    {
        $this->jwkset_manager = $jwkset_manager;

        return $this;
    }

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getJWKSetManager()
    {
        return $this->jwkset_manager;
    }
}
