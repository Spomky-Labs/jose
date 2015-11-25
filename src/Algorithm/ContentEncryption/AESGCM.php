<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

use Crypto\Cipher;
use Jose\Operation\ContentEncryptionInterface;

/**
 *
 */
abstract class AESGCM implements ContentEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent($data, $cek, $iv, $aad, $encoded_protected_header, &$tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $cipher->setAAD($calculated_aad);
        $cyphertext = $cipher->encrypt($data, $cek, $iv);
        $tag = $cipher->getTag();

        return $cyphertext;
    }

    /**
     *  {@inheritdoc}
     */
    public function decryptContent($data, $cek, $iv, $aad, $encoded_protected_header, $tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }
        $cipher->setTag($tag);
        $cipher->setAAD($calculated_aad);

        $plaintext = $cipher->decrypt($data, $cek, $iv);

        return $plaintext;
    }

    /**
     * @return int
     */
    public function getIVSize()
    {
        return 96;
    }

    /**
     * @return int
     */
    public function getCEKSize()
    {
        return $this->getKeySize();
    }

    /**
     * @return int
     */
    abstract protected function getKeySize();
}
