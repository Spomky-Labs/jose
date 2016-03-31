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

use Assert\Assertion;
use Jose\Factory\DecrypterFactory;
use Jose\Factory\VerifierFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\JWEInterface;
use Jose\Util\JWELoader;
use Jose\Util\JWSLoader;
use Psr\Log\LoggerInterface;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    /**
     * {@inheritdoc}
     */
    public static function loadAndDecryptUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, LoggerInterface $logger = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey($jwk);

        return self::loadAndDecrypt($input, $jwk_set, $allowed_algorithms, $logger);
    }

    /**
     * {@inheritdoc}
     */
    public static function loadAndDecryptUsingKeySet($input, JWKSetInterface $jwk_set, array $allowed_algorithms, LoggerInterface $logger = null)
    {
        return self::loadAndDecrypt($input, $jwk_set, $allowed_algorithms, $logger);
    }
    
    /**
     * {@inheritdoc}
     */
    public static function loadAndVerifySignatureUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, LoggerInterface $logger = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey($jwk);

        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $logger);
    }

    /**
     * {@inheritdoc}
     */
    public static function loadAndVerifySignatureUsingKeySet($input, JWKSetInterface $jwk_set, array $allowed_algorithms, LoggerInterface $logger = null)
    {
        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $logger);
    }

    /**
     * {@inheritdoc}
     */
    public static function loadAndVerifySignatureUsingKeyAndDetachedPayload($input, JWKInterface $jwk, array $allowed_algorithms, $detached_payload, LoggerInterface $logger = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey($jwk);

        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $logger);
    }

    /**
     * {@inheritdoc}
     */
    public static function loadAndVerifySignatureUsingKeySetAndDetachedPayload($input, JWKSetInterface $jwk_set, array $allowed_algorithms, $detached_payload, LoggerInterface $logger = null)
    {
        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $logger);
    }

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKSetInterface  $jwk_set
     * @param array                         $allowed_algorithms
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWEInterface
     */
    private static function loadAndDecrypt($input, JWKSetInterface $jwk_set, array $allowed_algorithms, LoggerInterface $logger = null)
    {
        $jwt = self::load($input);
        Assertion::isInstanceOf($jwt, JWEInterface::class, 'The input is not a valid JWE');
        $decrypted = DecrypterFactory::createDecrypter($allowed_algorithms, ['DEF', 'ZLIB', 'GZ'], $logger);

        $decrypted->decryptUsingKeySet($jwt, $jwk_set);

        return $jwt;
    }

    /**
     * @param string                        $input
     * @param \Jose\Object\JWKSetInterface  $jwk_set
     * @param array                         $allowed_algorithms
     * @param string|null                   $detached_payload
     * @param \Psr\Log\LoggerInterface|null $logger
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function loadAndVerifySignature($input, JWKSetInterface $jwk_set, array $allowed_algorithms, $detached_payload = null, LoggerInterface $logger = null)
    {
        $jwt = self::load($input);
        Assertion::isInstanceOf($jwt, JWSInterface::class, 'The input is not a valid JWS');
        $verifier = VerifierFactory::createVerifier($allowed_algorithms, $logger);

        $verifier->verifyWithKeySet($jwt, $jwk_set, $detached_payload);

        return $jwt;
    }

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
