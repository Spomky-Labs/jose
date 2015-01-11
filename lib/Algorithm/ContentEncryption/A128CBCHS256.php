<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A128CBCHS256 extends AESCBCHS
{
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    protected function getKeySize()
    {
        return 256;
    }

    public function getAlgorithmName()
    {
        return "A128CBC-HS256";
    }
}
