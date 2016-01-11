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

use Jose\Checker\CheckerManager;

final class CheckerManagerFactory
{
    /**
     * @param \Jose\Checker\CheckerInterface[] $checker_managers
     *
     * @return \Jose\Checker\CheckerManagerInterface
     */
    public static function createCheckerManager(array $checker_managers = [])
    {
        $checker = new CheckerManager();

        foreach ($checker_managers as $checker_manager) {
            $checker->addChecker($checker_manager);
        }

        return $checker;
    }
}
