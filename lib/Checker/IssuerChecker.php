<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class IssuerChecker implements CheckerInterface
{
    private $issuers = [];

    /**
     * @param string[] $issuers
     */
    public function __construct(array $issuers)
    {
        $this->issuers = $issuers;
    }

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $iss = $jwt->getIssuer();
        if (!is_null($iss) && !in_array($iss, $this->issuers)) {
            throw new \Exception('Issuer not allowed.');
        }

        return $this;
    }
}
