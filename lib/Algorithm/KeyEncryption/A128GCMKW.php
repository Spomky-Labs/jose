<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

/**
 * Class A128GCMKW.
 */
class A128GCMKW extends AESGCMKW
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
        return 'A128GCMKW';
    }
}
