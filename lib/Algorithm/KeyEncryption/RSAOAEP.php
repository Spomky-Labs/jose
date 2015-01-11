<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

class RSAOAEP extends RSA
{
    protected function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    protected function getHashAlgorithm()
    {
        return "sha1";
    }

    public function getAlgorithmName()
    {
        return "RSA-OAEP";
    }
}
