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

use Jose\JWSInterface;

/**
 * Class JWS.
 */
class JWS extends JWT implements JWSInterface
{
    use JWable;

    /**
     * @var string|null
     */
    protected $signature;

    /**
     * {@inheritdoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * {@inheritdoc}
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;

        return $this;
    }
}
