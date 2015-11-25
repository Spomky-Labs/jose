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

abstract class IssuerChecker implements CheckerInterface
{
    /**
     * @param string $issuer
     *
     * @return bool
     */
    abstract protected function isIssuerValid($issuer);

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $iss = $jwt->getIssuer();
        if (null !== $iss && !$this->isIssuerValid($iss)) {
            throw new \Exception('Issuer not allowed.');
        }
    }
}
