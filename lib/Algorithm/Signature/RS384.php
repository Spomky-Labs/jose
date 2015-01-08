<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

class RS384 extends RSA
{
    protected function getAlgorithm()
    {
        return "sha384";
    }

    protected function getSignatureMethod()
    {
        return CRYPT_RSA_SIGNATURE_PKCS1;
    }

    public function getAlgorithmName()
    {
        return "RS384";
    }
}
