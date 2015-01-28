<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

/**
 * Class RSAOAEP256
 * @package SpomkyLabs\Jose\Algorithm\KeyEncryption
 */
class RSAOAEP256 extends RSA
{
    /**
     * @return int
     */
    public function getEncryptionMode()
    {
        return CRYPT_RSA_ENCRYPTION_OAEP;
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return "sha256";
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "RSA-OAEP-256";
    }
}
