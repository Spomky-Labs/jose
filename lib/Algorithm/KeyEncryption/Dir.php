<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Base64Url\Base64Url;
use Jose\Operation\DirectEncryptionInterface;

class Dir implements DirectEncryptionInterface
{
    /**
     * @inheritdoc
     */
    public function getCEK(JWKInterface $key, array $header)
    {
        if ('dir' !== $key->getKeyType()) {
            throw new \InvalidArgumentException('The key is not valid');
        }

        return Base64Url::decode($key->getValue('dir'));
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'dir';
    }
}
