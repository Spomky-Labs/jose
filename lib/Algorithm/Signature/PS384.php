<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class PS384.
 */
class PS384 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return int
     */
    protected function getSignatureMethod()
    {
        return PHPSecLibRSA::SIGNATURE_PSS;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PS384';
    }
}
