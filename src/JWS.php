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
 * Class JWS.
 */
final class JWS extends JWT implements JWSInterface
{
    /**
     * @var string|null
     */
    protected $signature = null;

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
    public function withSignature($signature)
    {
        $jws = clone $this;
        $jws->signature = $signature;

        return $jws;
    }
}
