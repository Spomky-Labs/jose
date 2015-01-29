<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

/**
 * Class ECDHESA192KW
 * @package SpomkyLabs\Jose\Algorithm\KeyEncryption
 */
class ECDHESA192KW extends ECDHESAESKW
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
        return "ECDH-ES+A192KW";
    }
}
