<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

class PS384 extends RSA
{
    protected function getAlgorithm()
    {
        return "sha384";
    }

    protected function getSignatureMethod()
    {
        return CRYPT_RSA_SIGNATURE_PSS;
    }

    public function getAlgorithmName()
    {
        return "PS384";
    }
}
