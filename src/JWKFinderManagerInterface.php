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
    const KEY_TYPE_PRIVATE = 0x01;
    const KEY_TYPE_PUBLIC = 0x02;
    const KEY_TYPE_SYMMETRIC = 0x04;
    const KEY_TYPE_DIRECT = 0x08;
    const KEY_TYPE_NONE = 0x10;

    /**
     * @param \Jose\Finder\JWKFinderInterface $finder
     */
    public function addJWKFinder(JWKFinderInterface $finder);

    /**
     * Find key using the header.
     * This method will use JWK Finders and the header to identify a unique key ('kid', 'x5c', 'x5t'...).
     *
     * @param array $header The header
     * @param int   $key_type
     *
     * @return array Returns an array of keys found according to the header
     */
    public function findJWK(array $header, $key_type);
}
