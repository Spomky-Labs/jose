<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use SpomkyLabs\Jose\Util\RSAConverter;
use Jose\Operation\KeyEncryptionInterface;

abstract class RSA implements KeyEncryptionInterface
{
    /**
     * @inheritdoc
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e')));
        $rsa = $this->getRsaObject($values);

        return $rsa->encrypt($cek);
    }

    /**
     * @inheritdoc
     */
    public function decryptKey(JWKInterface $key, $encrypted_key, array $header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e', 'p', 'd', 'q', 'dp', 'dq', 'qi')));
        $rsa = $this->getRsaObject($values);

        return $rsa->decrypt($encrypted_key);
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
            throw new \InvalidArgumentException("The key is not a RSA key");
        }
    }

    abstract public function getEncryptionMode();
    abstract public function getHashAlgorithm();
}
