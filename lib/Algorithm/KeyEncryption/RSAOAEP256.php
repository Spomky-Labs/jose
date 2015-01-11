<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

class RSAOAEP256 extends RSA
{
    public function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm()
    {
        return "sha256";
    }

    public function getAlgorithmName()
    {
        return "RSA-OAEP-256";
    }
}
