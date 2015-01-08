<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

class PS256 extends RSA
{
    protected function getAlgorithm()
    {
        return "sha256";
    }

    protected function getSignatureMethod()
    {
        return CRYPT_RSA_SIGNATURE_PSS;
    }

    public function getAlgorithmName()
    {
        return "PS256";
    }
}
