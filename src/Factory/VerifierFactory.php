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

use Jose\Verifier;

final class VerifierFactory
{
    /**
     * @param string[]                         $algorithms
     * @param \Jose\Checker\CheckerInterface[] $checker_managers
     *
     * @return \Jose\VerifierInterface
     */
    public static function createVerifier(array $algorithms, array $checker_managers = [])
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);
        $checker_manager = CheckerManagerFactory::createCheckerManager($checker_managers);

        return new Verifier($algorithm_manager, $checker_manager);
    }
}
