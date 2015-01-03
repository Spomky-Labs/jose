<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyEncryptionInterface;

abstract class RSA implements KeyEncryptionInterface
{
    protected function checkKey(JWKInterface $key)
    {
        if ("RSA" !== $key->getKeyType()) {
            throw new \RuntimeException("The key is not a RSA key");
        }
    }
}
