<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

/**
 * Class RSA15.
 */
class RSA15 extends RSA
{
    /**
     * @return int
     */
    protected function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_PKCS1;
    }

    /**
     *
     */
    protected function getHashAlgorithm()
    {
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RSA1_5';
    }
}
