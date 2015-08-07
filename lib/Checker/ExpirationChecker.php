<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class ExpirationChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $exp = $jwt->getExpirationTime();
        if (!is_null($exp) && time() > $exp) {
            throw new \Exception('The JWT has expired.');
        }

        return $this;
    }
}
