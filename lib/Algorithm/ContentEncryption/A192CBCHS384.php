<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A192CBCHS384.
 */
class A192CBCHS384 extends AESCBCHS
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 384;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A192CBC-HS384';
    }
}
