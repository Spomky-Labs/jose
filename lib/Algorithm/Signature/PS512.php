<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

class PS512 extends RSA
{
    protected function getAlgorithm()
    {
        return "sha512";
    }

    protected function getSignatureMethod()
    {
        return CRYPT_RSA_SIGNATURE_PSS;
    }

    public function getAlgorithmName()
    {
        return "PS512";
    }
}
