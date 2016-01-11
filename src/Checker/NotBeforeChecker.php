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

final class NotBeforeChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('nbf')) {
            return;
        }
        $nbf = (int) $jwt->getClaim('nbf');
        if (time() < $nbf) {
            throw new \Exception('Can not use this JWT yet.');
        }
    }
}
