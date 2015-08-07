<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use phpseclib\Crypt\RSA as PHPSecLibRSA;

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
        return PHPSecLibRSA::ENCRYPTION_OAEP;
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha1';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RSA-OAEP';
    }
}
