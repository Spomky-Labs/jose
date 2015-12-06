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
 */
final class JWKManager implements JWKManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function createJWK(array $values = [])
    {
        $jwk = new JWK($values);

        return $jwk;
    }
}
