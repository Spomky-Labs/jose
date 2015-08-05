<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;
use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class RSAOAEP256.
 */
class RSAOAEP256 extends RSA
{
    /**
     * @return int
     */
    public function getEncryptionMode()
    {
        return PHPSecLibRSA::ENCRYPTION_OAEP;
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RSA-OAEP-256';
    }
}
