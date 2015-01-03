<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

/**
 * This class handles signatures using HMAC.
 * It supports HS384;
 */
class HS384 extends HMAC
{
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }
}
