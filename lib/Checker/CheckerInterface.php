<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

interface CheckerInterface
{
    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception If verification failed
     *
     * @return self
     */
    public function checkJWT(JWTInterface $jwt);
}
