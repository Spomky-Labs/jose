<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Base64Url\Base64Url;
use Jose\Object\JWE;
use Jose\Object\JWEInterface;
use Jose\Object\Recipient;
use Jose\Object\RecipientInterface;

final class JWELoader
{
    /**
     * @param array $data
     *
     * @return \Jose\Object\JWEInterface
     */
    public static function loadSerializedJsonJWE(array $data)
    {
        $jwe = new JWE();
        $jwe = $jwe->withCiphertext(Base64Url::decode($data['ciphertext']));

        self::populateIV($jwe, $data);
        self::populateAAD($jwe, $data);
        self::populateTag($jwe, $data);
        self::populateSharedProtectedHeaders($jwe, $data);
        self::populateSharedHeaders($jwe, $data);

        foreach ($data['recipients'] as $recipient) {
            $object = new Recipient();
            self::populateRecipientHeaders($object, $recipient);
            self::populateRecipientEncryptedKey($object, $recipient);

            $jwe = $jwe->addRecipient($object);
        }

        return $jwe;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param array                     $data
     */
    private static function populateIV(JWEInterface &$jwe, array $data)
    {
        if (array_key_exists('iv', $data)) {
            $jwe = $jwe->withIV(Base64Url::decode($data['iv']));
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param array                     $data
     */
    private static function populateAAD(JWEInterface &$jwe, array $data)
    {
        if (array_key_exists('aad', $data)) {
            $jwe = $jwe->withAAD($data['aad']);
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param array                     $data
     */
    private static function populateTag(JWEInterface &$jwe, array $data)
    {
        if (array_key_exists('tag', $data)) {
            $jwe = $jwe->withTag(Base64Url::decode($data['tag']));
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param array                     $data
     */
    private static function populateSharedProtectedHeaders(JWEInterface &$jwe, array $data)
    {
        if (array_key_exists('protected', $data)) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders($data['protected']);
            $jwe = $jwe->withSharedProtectedHeaders(json_decode(Base64Url::decode($data['protected']), true));
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     * @param array                     $data
     */
    private static function populateSharedHeaders(JWEInterface &$jwe, array $data)
    {
        if (array_key_exists('unprotected', $data)) {
            $jwe = $jwe->withSharedHeaders($data['unprotected']);
        }
    }

    /**
     * @param \Jose\Object\RecipientInterface $recipient
     * @param array                           $data
     */
    private static function populateRecipientHeaders(RecipientInterface &$recipient, array $data)
    {
        if (array_key_exists('header', $data)) {
            $recipient = $recipient->withHeaders($data['header']);
        }
    }

    /**
     * @param \Jose\Object\RecipientInterface $recipient
     * @param array                           $data
     */
    private static function populateRecipientEncryptedKey(RecipientInterface &$recipient, array $data)
    {
        if (array_key_exists('encrypted_key', $data)) {
            $recipient = $recipient->withEncryptedKey(Base64Url::decode($data['encrypted_key']));
        }
    }
}
