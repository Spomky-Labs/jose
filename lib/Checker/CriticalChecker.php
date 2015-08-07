<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class CriticalChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        $crit = $jwt->getCritical();
        if (!is_null($crit)) {
            foreach ($crit as $critical) {
                if (is_null($jwt->getHeaderValue($critical)) && is_null($jwt->getPayloadValue($critical))) {
                    throw new \Exception(sprintf("The claim/header '%s' is marked as critical but value is not set.", $critical));
                }
            }
        }

        return $this;
    }
}
