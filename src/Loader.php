<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Base64Url\Base64Url;
use Jose\Object\JWE;
use Jose\Object\JWEInterface;
use Jose\Object\JWS;
use Jose\Object\JWSInterface;
use Jose\Object\Recipient;
use Jose\Object\RecipientInterface;
use Jose\Object\Signature;
use Jose\Object\SignatureInterface;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    /**
     * Loader constructor.
     */
    private function __construct()
    {
    }

    /**
     * {@inheritdoc}
     */
    public static function load($input)
    {
        $json = self::convert($input);
        if (array_key_exists('signatures', $json)) {
            return self::loadSerializedJsonJWS($json);
        }
        if (array_key_exists('recipients', $json)) {
            return self::loadSerializedJsonJWE($json);
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * @param array $data
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function loadSerializedJsonJWS(array $data)
    {
        $jws = new JWS();

        self::populatePayload($jws, $data);

        foreach ($data['signatures'] as $signature) {
            $object = new Signature();
            $object = $object->withSignature(Base64Url::decode($signature['signature']));

            self::populateProtectedHeaders($object, $signature);
            self::populateHeaders($object, $signature);

            $jws = $jws->addSignature($object);
        }

        return $jws;
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     * @param array                           $data
     */
    private static function populateProtectedHeaders(SignatureInterface &$signature, array $data)
    {
        if (array_key_exists('protected', $data)) {
            $signature = $signature->withEncodedProtectedHeaders($data['protected']);
        }
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     * @param array                           $data
     */
    private static function populateHeaders(SignatureInterface &$signature, array $data)
    {
        if (array_key_exists('header', $data)) {
            $signature = $signature->withHeaders($data['header']);
        }
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param array                     $data
     */
    private static function populatePayload(JWSInterface &$jws, array $data)
    {
        if (array_key_exists('payload', $data)) {
            $payload = Base64Url::decode($data['payload']);
            $json = json_decode($payload, true);
            if (null !== $json && !empty($payload)) {
                $payload = $json;
            }
            $jws = $jws->withPayload($payload);
        }
    }

    /**
     * @param array $data
     *
     * @return \Jose\Object\JWEInterface
     */
    private static function loadSerializedJsonJWE(array $data)
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
            $jwe = $jwe->withAAD(Base64Url::decode($data['aad']));
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

    /**
     * @param string $input
     *
     * @return array
     */
    private static function convert($input)
    {
        if (is_array($data = json_decode($input, true))) {
            if (array_key_exists('signatures', $data) || array_key_exists('recipients', $data)) {
                return $data;
            } elseif (array_key_exists('signature', $data)) {
                return self::fromFlattenedSerializationSignatureToSerialization($data);
            } elseif (array_key_exists('ciphertext', $data)) {
                return self::fromFlattenedSerializationRecipientToSerialization($data);
            }
        } elseif (is_string($input)) {
            return self::fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }

    /**
     * @param $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationRecipientToSerialization($input)
    {
        $recipient = [];
        foreach (['header', 'encrypted_key'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipient[$key] = $input[$key];
            }
        }
        $recipients = [
            'ciphertext' => $input['ciphertext'],
            'recipients' => [$recipient],
        ];
        foreach (['ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipients[$key] = $input[$key];
            }
        }

        return $recipients;
    }

    /**
     * @param $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationSignatureToSerialization($input)
    {
        $signature = [
            'signature' => $input['signature'],
        ];
        foreach (['protected', 'header'] as $key) {
            if (array_key_exists($key, $input)) {
                $signature[$key] = $input[$key];
            }
        }

        $temp = [];
        if (!empty($input['payload'])) {
            $temp['payload'] = $input['payload'];
        }
        $temp['signatures'] = [$signature];

        return $temp;
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function fromCompactSerializationToSerialization($input)
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 3:
                return self::fromCompactSerializationSignatureToSerialization($parts);
            case 5:
                return self::fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationRecipientToSerialization(array $parts)
    {
        $recipient = [];
        if (!empty($parts[1])) {
            $recipient['encrypted_key'] = $parts[1];
        }

        $recipients = [
            'recipients' => [$recipient],
        ];
        foreach ([3 => 'ciphertext', 0 => 'protected', 2 => 'iv', 4 => 'tag'] as $part => $key) {
            if (!empty($parts[$part])) {
                $recipients[$key] = $parts[$part];
            }
        }

        return $recipients;
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationSignatureToSerialization(array $parts)
    {
        $temp = [];

        if (!empty($parts[1])) {
            $temp['payload'] = $parts[1];
        }
        $temp['signatures'] = [[
            'protected' => $parts[0],
            'signature' => $parts[2],
        ]];

        return $temp;
    }
}
