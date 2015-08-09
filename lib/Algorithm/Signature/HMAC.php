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

use Base64Url\Base64Url;
use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;.
 */
abstract class HMAC implements SignatureInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);

        return hex2bin(hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->getValue('k'))));
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($signature, $this->sign($key, $input));
        }

        return $this->timingSafeEquals($signature, $this->sign($key, $input));
    }

    /**
     * A timing safe equals comparison.
     *
     * @param string $signature   The internal signature to be checked
     * @param string $signedInput The signed input submitted value
     *
     * @return bool true if the two strings are identical.
     */
    public function timingSafeEquals($signature, $signedInput)
    {
        $signatureLength = strlen($signature);
        $signedInputLength = strlen($signedInput);
        $result = 0;

        if ($signedInputLength != $signatureLength) {
            return false;
        }

        for ($i = 0; $i < $signedInputLength; $i++) {
            $result |= (ord($signature[$i]) ^ ord($signedInput[$i]));
        }

        return $result === 0;
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->getKeyType() || null === $key->getValue('k')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
}
