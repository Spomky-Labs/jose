<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

class RS256 extends RSA
{
    protected function getAlgorithm()
    {
        return "sha256";
    }

    protected function getSignatureMethod()
    {
        return CRYPT_RSA_SIGNATURE_PKCS1;
    }

    public function getAlgorithmName()
    {
        return "RS256";
    }
}
