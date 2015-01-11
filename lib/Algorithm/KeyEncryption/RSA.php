<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use SpomkyLabs\Jose\Util\RSAConverter;
use Jose\Operation\KeyEncryptionInterface;

abstract class RSA implements KeyEncryptionInterface
{
    public function __construct()
    {
        if (!class_exists("\Crypt_RSA")) {
            throw new \RuntimeException("The library 'phpseclib/phpseclib' is required to use RSA based algorithms");
        }
    }

    /**
     * @inheritdoc
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e')));
        $rsa = $this->getRsaObject($values);

        try {
            return $rsa->encrypt($cek);
        } catch (\Exception $e) {
        }
    }

    /**
     * @inheritdoc
     */
    public function decryptKey(JWKInterface $key, $encrypted_key, array $header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e', 'p', 'd', 'q', 'dp', 'dq', 'qi')));
        $rsa = $this->getRsaObject($values);
        try {
            return $rsa->decrypt($encrypted_key);
        } catch (\Exception $e) {
        }
    }

    private function getRsaObject(array $values)
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($values);
        $encryption_mode = $this->getEncryptionMode();
        $rsa->setEncryptionMode($encryption_mode);
        if (CRYPT_RSA_ENCRYPTION_OAEP === $encryption_mode) {
            $rsa->setHash($this->getHashAlgorithm());
            $rsa->setMGFHash($this->getHashAlgorithm());
        }

        return $rsa;
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("RSA" !== $key->getKeyType()) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    abstract protected function getEncryptionMode();
    abstract protected function getHashAlgorithm();
}
