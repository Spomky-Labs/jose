<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS256;
 */
class HS256 extends HMAC
{
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    public function getAlgorithmName()
    {
        return "HS256";
    }
}
