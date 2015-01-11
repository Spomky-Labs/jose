<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A256CBCHS512 extends AESCBC_HS
{
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    protected function getKeySize()
    {
        return 512;
    }

    public function getAlgorithmName()
    {
        return "A256CBC-HS512";
    }
}
