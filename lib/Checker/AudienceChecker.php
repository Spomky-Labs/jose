<?php

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
