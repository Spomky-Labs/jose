<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

interface CheckerManagerInterface
{
    /**
     * @param \SpomkyLabs\Jose\Checker\CheckerInterface $checker
     *
     * @return self
     */
    public function addChecker(CheckerInterface $checker);

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception If verification failed
     *
     * @return self
     */
    public function checkJWT(JWTInterface $jwt);
}
