<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Checker\CheckerManagerInterface;

trait HasCheckerManager
{
    /**
     * @var \Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     *
     * @return self
     */
    private function setCheckerManager(CheckerManagerInterface $checker_manager)
    {
        $this->checker_manager = $checker_manager;

        return $this;
    }

    /**
     * @return \Jose\Checker\CheckerManagerInterface
     */
    private function getCheckerManager()
    {
        return $this->checker_manager;
    }
}
