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

use Jose\Finder\JWKFinderInterface;


interface JWKFinderManagerInterface
{
    /**
     * @param \Jose\Finder\JWKFinderInterface $finder
     */
    public function addJWKFinder(JWKFinderInterface $finder);

    /**
     * Find key using the header.
     * This method will use JWK Finders and the header to identify a unique key ('kid', 'x5c', 'x5t'...).
     *
     * @param array $header The header
     *
     * @return array Returns an array of keys found according to the header
     */
    public function findJWK(array $header);
}
