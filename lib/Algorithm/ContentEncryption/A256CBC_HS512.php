<?php

namespace SpomkyLabs\JOSE\Algorithm\ContentEncryption;

/**
 *
 */
class A256CBC_HS512 extends AESCBC_HS
{
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    protected function getKeySize()
    {
        return 512;
    }
}
