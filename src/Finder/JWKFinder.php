<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Finder;

/**
 */
final class JWKFinder implements JWKFinderInterface
{
    /**
     * {@inheritdoc}
     */
    public function findJWK(array $header)
    {
        if (!isset($header['jwk']) || !is_array($header['jwk'])) {
            return;
        }

        return $header['jwk'];
    }
}
