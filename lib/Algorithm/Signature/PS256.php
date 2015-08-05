<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class PS256.
 */
class PS256 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha256';
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
        return 'PS256';
    }
}
