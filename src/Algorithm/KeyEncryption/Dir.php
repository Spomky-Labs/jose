<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Object\JWKInterface;

final class Dir implements DirectEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWKInterface $key, array $header)
    {
        if (!$key->has('kty') || 'dir' !== $key->get('kty') || !$key->has('dir')) {
            throw new \InvalidArgumentException('The key is not valid');
        }

        return Base64Url::decode($key->get('dir'));
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'dir';
    }
}
