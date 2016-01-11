<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Jose\KeyConverter\KeyConverter;
use Jose\Object\JWKInterface;
use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class RSA.
 */
abstract class RSA implements KeyEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getAll(), array_flip(['n', 'e']));
        $rsa = $this->getRsaObject($values);

        try {
            $encrypted = $rsa->encrypt($cek);
            if (false === $encrypted) {
                return;
            }

            return $encrypted;
        } catch (\Exception $e) {
            //We catch the exception to return null.
            return;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptKey(JWKInterface $key, $encrypted_key, array $header)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getAll(), array_flip(['n', 'e', 'p', 'd', 'q', 'dp', 'dq', 'qi']));
        $rsa = $this->getRsaObject($values);

        try {
            $decrypted = $rsa->decrypt($encrypted_key);
            if (false === $decrypted) {
                return;
            }

            return $decrypted;
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
        $rsa = KeyConverter::fromArrayToRSACrypt($values);
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
        if (!$key->has('kty') || 'RSA' !== $key->get('kty')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    /**
     * @return int
     */
    abstract protected function getEncryptionMode();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
}
