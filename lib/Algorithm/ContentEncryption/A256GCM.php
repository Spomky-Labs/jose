<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A256GCM extends AESGCM
{
    protected function getKeySize()
    {
        return 256;
    }

    public function getAlgorithmName()
    {
        return "A256GCM";
    }
}
