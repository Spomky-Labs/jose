<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class IssuedAtChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $iat = $jwt->getIssuedAt();
        if (!is_null($iat) && time() < $iat) {
            throw new \Exception('The JWT is issued in the futur.');
        }

        return $this;
    }
}
