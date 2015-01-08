<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 *
 */
class A128GCM extends AESGCM
{
    protected function getKeySize()
    {
        return 128;
    }

    public function getAlgorithmName()
    {
        return "A128GCM";
    }
}
