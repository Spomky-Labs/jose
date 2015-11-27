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
use Jose\JWKInterface;
use Jose\Operation\DirectEncryptionInterface;

final class Dir implements DirectEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWKInterface $key, array $header)
    {
        if ('dir' !== $key->getKeyType()) {
            throw new \InvalidArgumentException('The key is not valid');
        }

        return Base64Url::decode($key->getValue('dir'));
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'dir';
    }
}
