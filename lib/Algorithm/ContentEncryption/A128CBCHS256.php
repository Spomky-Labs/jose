<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A128CBCHS256.
 */
class A128CBCHS256 extends AESCBCHS
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 256;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A128CBC-HS256';
    }
}
