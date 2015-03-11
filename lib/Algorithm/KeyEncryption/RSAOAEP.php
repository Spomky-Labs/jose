<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

/**
 * Class RSAOAEP.
 */
class RSAOAEP extends RSA
{
    /**
     * @return int
     */
    protected function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return "sha1";
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "RSA-OAEP";
    }
}
