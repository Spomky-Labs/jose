<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Base64Url\Base64Url;
use Jose\Operation\KeyEncryptionInterface;

abstract class AESKW implements KeyEncryptionInterface
{
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap(Base64Url::decode($key->getValue("k")), $cek);
    }

    public function decryptKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap(Base64Url::decode($key->getValue("k")), $encryted_cek);
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("oct" !== $key->getKeyType() || null === $key->getValue("k")) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    abstract protected function getWrapper();
}
