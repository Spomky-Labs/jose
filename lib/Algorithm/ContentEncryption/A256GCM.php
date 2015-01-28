<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A256GCM
 * @package SpomkyLabs\Jose\Algorithm\ContentEncryption
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
