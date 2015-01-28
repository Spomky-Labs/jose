<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS512;
 *
 * Class HS512
 * @package SpomkyLabs\Jose\Algorithm\Signature
 */
class HS512 extends HMAC
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "HS512";
    }
}
