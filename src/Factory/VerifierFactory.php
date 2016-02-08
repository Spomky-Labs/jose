<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\Verifier;

final class VerifierFactory
{
    /**
     * @param string[] $algorithms
     *
     * @return \Jose\VerifierInterface
     */
    public static function createVerifier(array $algorithms)
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);

        return new Verifier($algorithm_manager);
    }
}
