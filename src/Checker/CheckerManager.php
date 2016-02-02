<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Jose\Object\JWTInterface;

final class CheckerManager implements ClaimCheckerManagerInterface
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
    }

    /**
     * {@inheritdoc}
     */
    public function addChecker(ClaimCheckerInterface $checker)
    {
        $this->checkers[] = $checker;
    }

    /**
     * @return \Jose\Checker\ClaimCheckerInterface[]
     */
    private function getCheckers()
    {
        return $this->checkers;
    }
}
