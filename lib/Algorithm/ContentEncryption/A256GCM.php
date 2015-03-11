<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A256GCM.
 */
class A256GCM extends AESGCM
{
    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 256;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "A256GCM";
    }
}
