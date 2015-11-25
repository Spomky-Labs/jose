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

/**
 * Interface representing a JSON Web Key Manager.
 */
interface JWKManagerInterface
{
    /**
     * @param \Jose\Finder\JWKFinderInterface $finder
     *
     * @return self
     */
    public function addJWKFinder(JWKFinderInterface $finder);

    /**
     * Find key using the header.
     * This method will use JWK Finders and the header to identify a unique key ('kid', 'x5c', 'x5t'...).
     *
     * @param array $header The header
     *
     * @return \Jose\JWKInterface|null Returns a JWKInterface object according to the header or null
     */
    public function findJWK(array $header);

    /**
     * Create a JWK object.
     *
     * @param array $values The values to set.
     *
     * @return \Jose\JWKInterface Returns a JWKInterface object
     */
    public function createJWK(array $values = []);
}
