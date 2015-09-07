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

use Jose\JWKManagerInterface;

trait HasJWKManager
{
    /**
     * @var \Jose\JWKManagerInterface
     */
    private $jwk_manager;

    /**
     * @param \Jose\JWKManagerInterface $jwk_manager
     *
     * @return self
     */
    public function setJWKManager(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;

        return $this;
    }

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getJWKManager()
    {
        return $this->jwk_manager;
    }
}
