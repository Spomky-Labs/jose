<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Crypto\Cipher;
use Jose\JWKInterface;
use SpomkyLabs\Jose\Util\Base64Url;
use Jose\Operation\KeyEncryptionInterface;

abstract class AESGCMKW implements KeyEncryptionInterface
{
    public function __construct()
    {
        if (!class_exists("\Crypto\Cipher")) {
            throw new \RuntimeException("The PHP extension 'Crypto' is required to use AES GCM based algorithms");
        }
    }

    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);

        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setAAD(null);
        $iv = openssl_random_pseudo_bytes(96/8);
        $encryted_cek = $cipher->encrypt($cek, Base64Url::decode($key->getValue('k')), $iv);

        $header['iv'] = Base64Url::encode($iv);
        $header['tag'] = Base64Url::encode($cipher->getTag(16));

        return $encryted_cek;
    }

    public function decryptKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($header);

        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setTag(Base64Url::decode($header['tag']));
        $cipher->setAAD(null);

        $cek = $cipher->decrypt($encryted_cek, Base64Url::decode($key->getValue('k')), Base64Url::decode($header['iv']));

        return $cek;
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("oct" !== $key->getKeyType() || null === $key->getValue("k")) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    protected function checkAdditionalParameters(array $header)
    {
        if (null === $header["iv"] || null === $header["tag"]) {
            throw new \InvalidArgumentException("Parameters 'iv' or 'tag' are missing.");
        }
    }

    abstract protected function getKeySize();
}
