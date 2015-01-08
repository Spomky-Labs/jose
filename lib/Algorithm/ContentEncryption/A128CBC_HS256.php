<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A128CBC_HS256 extends AESCBC_HS
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
