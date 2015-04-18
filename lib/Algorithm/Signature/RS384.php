<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * Class RS384.
 */
class RS384 extends RSA
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
        return CRYPT_RSA_SIGNATURE_PKCS1;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "RS384";
    }
}
