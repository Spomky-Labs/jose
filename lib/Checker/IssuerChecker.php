<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class IssuerChecker implements CheckerInterface
{
    private $issuers = array();

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
