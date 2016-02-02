<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Checker\ClaimCheckerManagerInterface;

trait HasClaimCheckerManager
{
    /**
     * @var \Jose\Checker\ClaimCheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @param \Jose\Checker\ClaimCheckerManagerInterface $checker_manager
     */
    private function setClaimCheckerManager(ClaimCheckerManagerInterface $checker_manager)
    {
        $this->checker_manager = $checker_manager;
    }

    /**
     * @return \Jose\Checker\ClaimCheckerManagerInterface
     */
    private function getClaimCheckerManager()
    {
        return $this->checker_manager;
    }
}
