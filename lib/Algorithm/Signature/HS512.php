<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

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
}
