<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

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
}
