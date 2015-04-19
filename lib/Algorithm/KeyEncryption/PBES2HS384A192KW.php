<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

/**
 * Class PBES2HS384A192KW.
 */
class PBES2HS384A192KW extends PBES2AESKW
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
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return float
     */
    protected function getKeySize()
    {
        return 192 / 8;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PBES2-HS384+A192KW';
    }
}
