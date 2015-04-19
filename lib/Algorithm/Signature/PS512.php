<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * Class PS512.
 */
class PS512 extends RSA
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
        return CRYPT_RSA_SIGNATURE_PSS;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PS512';
    }
}
