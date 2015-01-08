<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS512;
 */
class HS512 extends HMAC
{
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    public function getAlgorithmName()
    {
        return "HS512";
    }
}
