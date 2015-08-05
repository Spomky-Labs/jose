<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class RS512.
 */
class RS512 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @return int
     */
    protected function getSignatureMethod()
    {
        return PHPSecLibRSA::SIGNATURE_PKCS1;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RS512';
    }
}
