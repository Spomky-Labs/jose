<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Base64Url\Base64Url;
use Jose\Object\JWE;
use Jose\Object\JWS;
use Jose\Object\Recipient;
use Jose\Object\Signature;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    /**
     * Loader constructor.
     */
    private function __construct() {}

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
            return self::loadSerializedJsonJWE($json, $input);
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * @param array  $data
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWSInterface[]
     */
    private static function loadSerializedJsonJWS(array $data)
    {
        $jws = new JWS();
        if (array_key_exists('payload', $data)) {
            $jws = $jws->withPayload(Base64Url::decode($data['payload']));
        }

        foreach ($data['signatures'] as $signature) {
            $object = new Signature();
            $object = $object->withSignature(Base64Url::decode($signature['signature']));
            if (array_key_exists('protected', $signature)) {
                $object = $object->withEncodedProtectedHeaders($signature['protected']);
            }
            if (array_key_exists('header', $signature)) {
                $object = $object->withHeaders($signature['header']);
            }

            $jws = $jws->addSignature($object);
        }

        return $jws;
    }

    /**
     * @param array  $data
     * @param string $input
     *
     * @return \Jose\Object\JWEInterface|\Jose\Object\JWEInterface[]
     */
    private static function loadSerializedJsonJWE(array $data, $input)
    {
        $jwe = new JWE();
        $jwe = $jwe->withCiphertext(Base64Url::decode($data['ciphertext']));
        if (array_key_exists('iv', $data)) {
            $jwe = $jwe->withIV(Base64Url::decode($data['iv']));
        }
        if (array_key_exists('aad', $data)) {
            $jwe = $jwe->withAAD(Base64Url::decode($data['aad']));
        }
        if (array_key_exists('tag', $data)) {
            $jwe = $jwe->withTag(Base64Url::decode($data['tag']));
        }
        if (array_key_exists('protected', $data)) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders($data['protected']);
            $jwe = $jwe->withSharedProtectedHeaders(json_decode(Base64Url::decode($data['protected']), true));
        }
        if (array_key_exists('unprotected', $data)) {
            $jwe = $jwe->withSharedHeaders($data['unprotected']);
        }
        foreach ($data['recipients'] as $recipient) {
            $object = new Recipient();
            if (array_key_exists('header', $recipient)) {
                $object = $object->withHeaders($recipient['header']);
            }
            if (array_key_exists('encrypted_key', $recipient)) {
                $object = $object->withEncryptedKey(Base64Url::decode($recipient['encrypted_key']));
            }

            $jwe = $jwe->addRecipient($object);
        }

        return $jwe;
    }

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
     * @param $input
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
