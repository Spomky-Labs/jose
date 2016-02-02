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

abstract class SubjectChecker implements ClaimCheckerInterface
{
    /**
     * @param string $subject
     *
     * @return bool
     */
    abstract protected function isSubjectValid($subject);

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('sub')) {
            return;
        }
        $sub = $jwt->getClaim('sub');
        if (!$this->isSubjectValid($sub)) {
            throw new \Exception('Invalid subject.');
        }
    }
}
