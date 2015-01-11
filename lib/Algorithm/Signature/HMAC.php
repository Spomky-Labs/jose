<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use SpomkyLabs\Jose\Util\Base64Url;
use Jose\Operation\SignatureInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;
 */
abstract class HMAC implements SignatureInterface
{
    /**
     * @inheritdoc
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);

        return hex2bin(hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->getValue('k'))));
    }

    /**
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        return $signature === $this->sign($key, $input);
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("oct" !== $key->getKeyType() || null === $key->getValue("k")) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
}
