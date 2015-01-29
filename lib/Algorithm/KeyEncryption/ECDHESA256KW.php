<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

/**
 * Class ECDHESA256KW
 * @package SpomkyLabs\Jose\Algorithm\KeyEncryption
 */
class ECDHESA256KW extends ECDHESAESKW
{
    /**
     * @return Wrapper
     */
    protected function getWrapper()
    {
        return new Wrapper();
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "ECDH-ES+A256KW";
    }
}
