<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A192GCM.
 */
class A192GCM extends AESGCM
{
    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 192;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A192GCM';
    }
}
