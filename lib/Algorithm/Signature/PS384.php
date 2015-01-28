<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * Class PS384
 * @package SpomkyLabs\Jose\Algorithm\Signature
 */
class PS384 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return "sha384";
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
        return "PS384";
    }
}
