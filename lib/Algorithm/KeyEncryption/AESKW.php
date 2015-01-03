<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use SpomkyLabs\JOSE\Util\Base64Url;
use Jose\Operation\KeyWrappingInterface;

abstract class AESKW implements KeyWrappingInterface
{
    public function wrapKey(JWKInterface $key, $cek)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap(Base64Url::decode($key->getValue("k")), $cek);
    }

    public function unwrapKey(JWKInterface $key, $encryted_cek)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap(Base64Url::decode($key->getValue("k")), $encryted_cek);
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("oct" !== $key->getKeyType() || null === $key->getValue("k")) {
            throw new \RuntimeException("The key is not valid");
        }
    }

    abstract protected function getWrapper();
}
