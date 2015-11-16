<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose;

use Jose\JWTManagerInterface;

/**
 * Class representing a JSON Web Signature.
 */
class JWTManager implements JWTManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function createJWT()
    {
        return new JWT();
    }

    /**
     * {@inheritdoc}
     */
    public function createJWS()
    {
        return new JWS();
    }

    /**
     * {@inheritdoc}
     */
    public function createJWE()
    {
        return new JWE();
    }
}
