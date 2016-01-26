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

final class CriticalChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        if (!$jwt->hasProtectedHeader('crit')) {
            return;
        }
        $crit = $jwt->getProtectedHeader('crit');
        if (!is_array($crit)) {
            throw new \RuntimeException('The header "crit" must contain an array');
        }

        foreach ($crit as $critical) {
            if (!$jwt->hasHeaderOrClaim($critical)) {
                throw new \Exception(sprintf("The claim/header '%s' is marked as critical but value is not set.", $critical));
            }
        }
    }
}
