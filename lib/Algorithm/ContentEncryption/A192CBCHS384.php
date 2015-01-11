<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A192CBCHS384 extends AESCBCHS
{
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    protected function getKeySize()
    {
        return 384;
    }

    public function getAlgorithmName()
    {
        return "A192CBC-HS384";
    }
}
