<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

class RSA1_5 extends RSA
{
    public function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_PKCS1;
    }

    public function getHashAlgorithm()
    {
    }

    public function getAlgorithmName()
    {
        return "RSA1_5";
    }
}
