<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext).
 */
class None implements SignatureInterface
{
    /**
     * @inheritdoc
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);

        return '';
    }

    /**
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        return $signature === $this->sign($key, $data);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ("none" !== $key->getKeyType()) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "none";
    }
}
