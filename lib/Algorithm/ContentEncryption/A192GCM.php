<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A192GCM extends AESGCM
{
    protected function getKeySize()
    {
        return 192;
    }

    public function getAlgorithmName()
    {
        return "A192GCM";
    }
}
