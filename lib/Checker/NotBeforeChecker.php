<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class NotBeforeChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $nbf = $jwt->getNotBefore();
        if (!is_null($nbf) && time() < $nbf) {
            throw new \Exception('Can not use this JWT yet.');
        }

        return $this;
    }
}
