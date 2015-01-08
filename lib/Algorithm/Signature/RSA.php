<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;
use SpomkyLabs\Jose\Util\RSAConverter;

abstract class RSA implements SignatureInterface
{
    abstract protected function getAlgorithm();
    abstract protected function getSignatureMethod();

    /**
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e')));
        $rsa = RSAConverter::fromArrayToRSA_Crypt($values);

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === CRYPT_RSA_SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getAlgorithm());
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod());

        return $rsa->verify($input, $signature);
    }

    /**
     * @inheritdoc
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e', 'p', 'd', 'q', 'dp', 'dq', 'qi')));
        $rsa = RSAConverter::fromArrayToRSA_Crypt($values);

        if ($rsa->getPrivateKey() === null) {
            throw new \InvalidArgumentException("The key is not a private key");
        }

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === CRYPT_RSA_SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getAlgorithm());
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod());

        $result = $rsa->sign($input);
        if ($result === false) {
            throw new \RuntimeException("An error occured during the creation of the signature");
        }

        return $result;
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("RSA" !== $key->getKeyType()) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }
}
