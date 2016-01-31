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

use Jose\Util\JWELoader;
use Jose\Util\JWSLoader;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    /**
     * {@inheritdoc}
     */
    public static function load($input)
    {
        $json = self::convert($input);
        if (array_key_exists('signatures', $json)) {
            return JWSLoader::loadSerializedJsonJWS($json);
        }
        if (array_key_exists('recipients', $json)) {
            return JWELoader::loadSerializedJsonJWE($json);
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
