<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Jose\KeyConverter\KeyConverter;
use Jose\Object\JWKInterface;

/**
 * Class RSA.
 */
abstract class RSA implements SignatureInterface
{
    /**
     * @return mixed
     */
    abstract protected function getAlgorithm();

    /**
     * @return mixed
     */
    abstract protected function getSignatureMethod();

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        $this->checkKey($key);

        $values = array_intersect_key($key->getAll(), array_flip(['n', 'e']));
        $rsa = KeyConverter::fromArrayToRSACrypt($values);

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === \phpseclib\Crypt\RSA::SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getAlgorithm());
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod());

        return $rsa->verify($input, $signature);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);

        $values = array_intersect_key($key->getAll(), array_flip(['n', 'e', 'p', 'd', 'q', 'dp', 'dq', 'qi']));
        $rsa = KeyConverter::fromArrayToRSACrypt($values);

        if ($rsa->getPrivateKey() === false) {
            throw new \InvalidArgumentException('The key is not a private key');
        }

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === \phpseclib\Crypt\RSA::SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getAlgorithm());
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod());

        $result = $rsa->sign($input);
        if ($result === false) {
            throw new \RuntimeException('An error occurred during the creation of the signature');
        }

        return $result;
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
}
