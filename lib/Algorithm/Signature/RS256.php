<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * Class RS256
 * @package SpomkyLabs\Jose\Algorithm\Signature
 */
class RS256 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return "sha256";
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
        return "RS256";
    }
}
