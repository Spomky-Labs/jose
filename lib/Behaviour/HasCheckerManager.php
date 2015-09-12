<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Behaviour;

use SpomkyLabs\Jose\Checker\CheckerManagerInterface;

trait HasCheckerManager
{
    /**
     * @var \SpomkyLabs\Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @param \SpomkyLabs\Jose\Checker\CheckerManagerInterface $checker_manager
     *
     * @return self
     */
    public function setCheckerManager(CheckerManagerInterface $checker_manager)
    {
        $this->checker_manager = $checker_manager;

        return $this;
    }

    /**
     * @return \SpomkyLabs\Jose\Checker\CheckerManagerInterface
     */
    protected function getCheckerManager()
    {
        return $this->checker_manager;
    }
}
