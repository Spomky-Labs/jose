<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use SpomkyLabs\Jose\Util\RSAConverter;
use Jose\Operation\KeyEncryptionInterface;
use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class RSA.
 */
abstract class RSA implements KeyEncryptionInterface
{
    /**
     *
     */
    public function __construct()
    {
        if (!class_exists("\phpseclib\Crypt\RSA")) {
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
            //We catch the exception to return null.
            return;
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
            //We catch the exception to return null.
            return;
        }
    }

    /**
     * @param array $values
     *
     * @return \phpseclib\Crypt\RSA
     */
    private function getRsaObject(array $values)
    {
        $rsa = RSAConverter::fromArrayToRSACrypt($values);
        $encryption_mode = $this->getEncryptionMode();
        $rsa->setEncryptionMode($encryption_mode);
        if (PHPSecLibRSA::ENCRYPTION_OAEP === $encryption_mode) {
            $rsa->setHash($this->getHashAlgorithm());
            $rsa->setMGFHash($this->getHashAlgorithm());
        }

        return $rsa;
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('RSA' !== $key->getKeyType()) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    /**
     * @return mixed
     */
    abstract protected function getEncryptionMode();

    /**
     * @return mixed
     */
    abstract protected function getHashAlgorithm();
}
