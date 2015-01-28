<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS384;
 */
/**
 * Class HS384
 * @package SpomkyLabs\Jose\Algorithm\Signature
 */
class HS384 extends HMAC
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "HS384";
    }
}
