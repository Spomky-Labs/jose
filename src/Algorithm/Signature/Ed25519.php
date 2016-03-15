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

/**
 * Class Ed25519.
 */
class Ed25519 implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);
        if (!$key->has('d')) {
            throw new \InvalidArgumentException('The key is not private');
        }

        $secret = Base64Url::decode($key->get('d'));
        $public = Base64Url::decode($key->get('x'));

        $signature = ed25519_sign($data, $secret, $public);

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        $this->checkKey($key);

        $public = Base64Url::decode($key->get('x'));

        return ed25519_sign_open($data, $public, $signature);
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        if ('OKP' !== $key->get('kty')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
        if (!$key->has('x') || !$key->has('crv')) {
            throw new \InvalidArgumentException('Key components ("x" or "crv") missing');
        }
        if ('Ed25519' !== $key->get('crv')) {
            throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'Ed25519';
    }
}
