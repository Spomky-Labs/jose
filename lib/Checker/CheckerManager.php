<?php

namespace SpomkyLabs\Jose\Checker;

use Jose\JWTInterface;

class CheckerManager implements CheckerManagerInterface
{
    /**
     * @var \SpomkyLabs\Jose\Checker\CheckerInterface[]
     */
    private $checkers = array();

    /**
     * {@inheritdoc}
     */
    public function checkJWT(JWTInterface $jwt)
    {
        foreach ($this->getCheckers() as $checker) {
            $checker->checkJWT($jwt);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function addChecker(CheckerInterface $checker)
    {
        $this->checkers[] = $checker;

        return $this;
    }

    /**
     * @return \SpomkyLabs\Jose\Checker\CheckerInterface[]
     */
    private function getCheckers()
    {
        return $this->checkers;
    }
}
