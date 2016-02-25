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

use Jose\Signer;
use Psr\Log\LoggerInterface;

final class SignerFactory
{
    /**
     * @param string[]                      $algorithms
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\SignerInterface
     */
    public static function createSigner(array $algorithms, LoggerInterface $logger = null)
    {
        $algorithm_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);

        return new Signer($algorithm_manager, $logger);
    }
}
