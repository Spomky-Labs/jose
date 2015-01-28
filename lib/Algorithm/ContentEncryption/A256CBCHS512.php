<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A256CBCHS512
 * @package SpomkyLabs\Jose\Algorithm\ContentEncryption
 */
class A256CBCHS512 extends AESCBCHS
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 512;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "A256CBC-HS512";
    }
}
