<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;
use SpomkyLabs\Jose\Util\RSAConverter;
use phpseclib\Crypt\RSA as PHPSecLibRSA;

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
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        $this->checkKey($key);
        $values = array_intersect_key($key->getValues(), array_flip(array('n', 'e')));
        $rsa = RSAConverter::fromArrayToRSACrypt($values);

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === PHPSecLibRSA::SIGNATURE_PSS) {
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
        $rsa = RSAConverter::fromArrayToRSACrypt($values);

        if ($rsa->getPrivateKey() === false) {
            throw new \InvalidArgumentException('The key is not a private key');
        }

        $rsa->setHash($this->getAlgorithm());
        if ($this->getSignatureMethod() === PHPSecLibRSA::SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getAlgorithm());
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod());

        $result = $rsa->sign($input);
        if ($result === false) {
            throw new \RuntimeException('An error occured during the creation of the signature');
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
