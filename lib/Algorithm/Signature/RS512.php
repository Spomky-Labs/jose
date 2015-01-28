<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * Class RS512
 * @package SpomkyLabs\Jose\Algorithm\Signature
 */
class RS512 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return "sha512";
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
        return "RS512";
    }
}
