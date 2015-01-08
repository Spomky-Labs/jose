<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

class RSA_OAEP extends RSA
{
    public function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm()
    {
        return "sha1";
    }

    public function getAlgorithmName()
    {
        return "RSA-OAEP";
    }
}
