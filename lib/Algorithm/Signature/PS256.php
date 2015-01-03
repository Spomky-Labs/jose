<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

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
}
