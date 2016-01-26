<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\Signer;

final class SignerFactory
{
    /**
     * SignerFactory constructor.
     *
     * This factory is not supposed to be instantiated
     */
    private function __construct() {}

    /**
     * @param string[] $algorithms
     *
     * @return \Jose\SignerInterface
     */
    public static function createSigner(array $algorithms)
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);

        return new Signer($algorithm_manager);
    }
}
