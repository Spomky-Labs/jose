<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

class RSA_OAEP_256 extends RSA
{
    public function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm()
    {
        return "sha256";
    }
}
