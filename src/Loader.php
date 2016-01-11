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
use Jose\Behaviour\HasPayloadConverter;
use Jose\Object\JWE;
use Jose\Object\JWS;
use Jose\Payload\PayloadConverterManagerInterface;
use Jose\Util\Converter;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    use HasPayloadConverter;

    /**
     * Loader constructor.
     *
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter_manager
     */
    public function __construct(PayloadConverterManagerInterface $payload_converter_manager)
    {
        $this->setPayloadConverter($payload_converter_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function load($input)
    {
        $json = json_decode(Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION), true);
        if (is_array($json)) {
            if (array_key_exists('signatures', $json)) {
                return $this->loadSerializedJsonJWS($json, $input);
            }
            if (array_key_exists('recipients', $json)) {
                return $this->loadSerializedJsonJWE($json, $input);
            }
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * @param array  $data
     * @param string $input
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWSInterface[]
     */
    private function loadSerializedJsonJWS(array $data, $input)
    {
        $encoded_payload = array_key_exists('payload', $data) ? $data['payload'] : null;
        $payload = null === $encoded_payload ? null : Base64Url::decode($encoded_payload);

        $jws = [];
        foreach ($data['signatures'] as $signature) {
            if (array_key_exists('protected', $signature)) {
                $encoded_protected_header = $signature['protected'];
                $protected_header = json_decode(Base64Url::decode($encoded_protected_header), true);
            } else {
                $encoded_protected_header = null;
                $protected_header = [];
            }
            $unprotected_header = isset($signature['header']) ? $signature['header'] : [];
            $tmp = $this->getPayloadConverter()->convertStringToPayload(
                array_merge($protected_header, $unprotected_header),
                $payload
            );

            $result = new JWS(
                $input,
                Base64Url::decode($signature['signature']),
                $encoded_payload,
                $tmp,
                $encoded_protected_header,
                $unprotected_header
            );
            $jws[] = $result;
        }

        return count($jws) > 1 ? $jws : current($jws);
    }

    /**
     * @param array  $data
     * @param string $input
     *
     * @return \Jose\Object\JWEInterface|\Jose\Object\JWEInterface[]
     */
    private function loadSerializedJsonJWE(array $data, $input)
    {
        $result = [];
        foreach ($data['recipients'] as $recipient) {
            $encoded_protected_header = array_key_exists('protected', $data) ? $data['protected'] : null;
            $unprotected_header = array_key_exists('unprotected', $data) ? $data['unprotected'] : [];
            $header = array_key_exists('header', $recipient) ? $recipient['header'] : [];

            $jwe = new JWE(
                $input,
                Base64Url::decode($data['ciphertext']),
                array_key_exists('encrypted_key', $recipient) ? Base64Url::decode($recipient['encrypted_key']) : null,
                array_key_exists('iv', $data) ? Base64Url::decode($data['iv']) : null,
                array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null,
                array_key_exists('tag', $data) ? Base64Url::decode($data['tag']) : null,
                $encoded_protected_header,
                array_merge($unprotected_header, $header)
            );
            $result[] = $jwe;
        }

        return count($result) > 1 ? $result : current($result);
    }
}
