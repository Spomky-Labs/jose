<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS256;.
 */
/**
 * Class HS256.
 */
class HS256 extends HMAC
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "HS256";
    }
}
