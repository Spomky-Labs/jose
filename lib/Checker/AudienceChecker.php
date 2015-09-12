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

class AudienceChecker implements CheckerInterface
{
    private $audience;

    /**
     * @param string $audience
     */
    public function __construct($audience)
    {
        $this->audience = $audience;
    }

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $aud = $jwt->getAudience();
        if (!is_null($aud) && $this->audience !== $aud) {
            throw new \Exception('Bad audience.');
        }

        return $this;
    }
}
