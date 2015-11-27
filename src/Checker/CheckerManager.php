<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Jose\JWTInterface;

final class CheckerManager implements CheckerManagerInterface
{
    /**
     * @var \Jose\Checker\CheckerInterface[]
     */
    private $checkers = [];

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        foreach ($this->getCheckers() as $checker) {
            $checker->checkJWT($jwt);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function addChecker(CheckerInterface $checker)
    {
        $this->checkers[] = $checker;

        return $this;
    }

    /**
     * @return \Jose\Checker\CheckerInterface[]
     */
    private function getCheckers()
    {
        return $this->checkers;
    }
}
