<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A128GCM
 * @package SpomkyLabs\Jose\Algorithm\ContentEncryption
 */
class A128GCM extends AESGCM
{
    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 128;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "A128GCM";
    }
}
