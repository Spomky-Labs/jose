<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

class RSA15 extends RSA
{
    protected function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_PKCS1;
    }

    protected function getHashAlgorithm()
    {
    }

    public function getAlgorithmName()
    {
        return "RSA1_5";
    }
}
