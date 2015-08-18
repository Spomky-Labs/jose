<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;
use phpseclib\Crypt\RSA as PHPSecLibRSA;
use SpomkyLabs\Jose\KeyConverter\RSAKey;

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
        $pem = RSAKey::toPublic(new RSAKey($key));

        $rsa = new PHPSecLibRSA();

        $rsa->loadKey($pem->toPEM());
        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === PHPSecLibRSA::SIGNATURE_PSS) {
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
        $pem = new RSAKey($key);

        if (!$pem->isPrivate()) {
            throw new \InvalidArgumentException('The key is not a private key');
        }

        $rsa = new PHPSecLibRSA();

        $rsa->loadKey($pem->toPEM());
        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === PHPSecLibRSA::SIGNATURE_PSS) {
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
        if ('RSA' !== $key->getKeyType()) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }
}
