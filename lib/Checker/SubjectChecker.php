<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

abstract class SubjectChecker implements CheckerInterface
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
        $sub = $jwt->getSubject();
        if (null !== $sub && !$this->isSubjectValid($sub)) {
            throw new \Exception('Invalid subject.');
        }

        return $this;
    }
}
