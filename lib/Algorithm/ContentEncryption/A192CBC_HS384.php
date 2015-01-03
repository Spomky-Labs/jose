<?php

namespace SpomkyLabs\JOSE\Algorithm\ContentEncryption;

/**
 *
 */
class A192CBC_HS384 extends AESCBC_HS
{
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    protected function getKeySize()
    {
        return 384;
    }
}
