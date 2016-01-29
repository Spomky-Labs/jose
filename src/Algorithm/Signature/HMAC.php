<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Base64Url\Base64Url;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKInterface;
use Jose\Util\StringUtil;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;.
 */
abstract class HMAC implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->get('k')), true);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        return $this->compareHMAC($this->sign($key, $input), $signature);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->get('kty') || !$key->has('k')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }

    protected function compareHMAC($safe, $user)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safe, $user);
        }
        $safeLen = StringUtil::strlen($safe);
        $userLen = StringUtil::strlen($user);

        if ($userLen !== $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; $i++) {
            $result |= (ord($safe[$i]) ^ ord($user[$i]));
        }

        return $result === 0;
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
}
