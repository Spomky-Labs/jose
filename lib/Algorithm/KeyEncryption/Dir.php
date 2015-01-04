<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\DirectEncryptionInterface;

/**
 */
class Dir implements DirectEncryptionInterface
{
    /**
     * @inheritdoc
     */
    public function getCEK(JWKInterface $key, array &$header)
    {
        if ("dir" !== $key->getType()) {
            throw new \InvalidArgumentException("The key is not a direct key");
        }
        $cek = $key->getValue('dir');
        if (empty($cek) || !is_string($cek)) {
            throw new \InvalidArgumentException("The key does not have 'dir' parameter or parameter returned an invalid value");
        }

        return $cek;
    }

    public function getAlgorithmName()
    {
        return "Dir";
    }
}
