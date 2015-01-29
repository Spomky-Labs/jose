<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

/**
 * Class ECDHESA128KW
 * @package SpomkyLabs\Jose\Algorithm\KeyEncryption
 */
class ECDHESA128KW extends ECDHESAESKW
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
        return "ECDH-ES+A128KW";
    }
}
