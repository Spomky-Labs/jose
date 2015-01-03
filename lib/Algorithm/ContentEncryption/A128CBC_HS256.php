<?php

namespace SpomkyLabs\JOSE\Algorithm\ContentEncryption;

/**
 *
 */
class A128CBC_HS256 extends AESCBC_HS
{
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    protected function getKeySize()
    {
        return 256;
    }
}
