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
use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\Signature\SignatureInterface;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasPayloadConverter;
use Jose\Object\JWKInterface;
use Jose\Object\SignatureInstructionInterface;
use Jose\Payload\PayloadConverterManagerInterface;
use Jose\Util\Converter;

/**
 */
final class Signer implements SignerInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasPayloadConverter;

    /**
     * Signer constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface            $jwa_manager
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter_manager
     */
    public function __construct(JWAManagerInterface $jwa_manager, PayloadConverterManagerInterface $payload_converter_manager) {
        $this->setJWAManager($jwa_manager);
        $this->setPayloadConverter($payload_converter_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function sign($input, array $instructions, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $detached_signature = false, &$detached_payload = null)
    {
        $additional_header = [];
        $input = $this->getPayloadConverter()->convertPayloadToString($additional_header, $input);
        $this->checkInstructions($instructions, $serialization);

        $jwt_payload = Base64Url::encode($input);

        $signatures = [
            'payload'    => $jwt_payload,
            'signatures' => [],
        ];

        foreach ($instructions as $instruction) {
            $signatures['signatures'][] = $this->computeSignature($instruction, $jwt_payload, $additional_header);
        }

        if (true === $detached_signature) {
            $detached_payload = $signatures['payload'];
            unset($signatures['payload']);
        }

        return Converter::convert($signatures, $serialization);
    }

    /**
     * @param \Jose\Object\SignatureInstructionInterface $instruction
     * @param string                                     $jwt_payload
     * @param array                                      $additional_header
     *
     * @return array
     */
    protected function computeSignature(SignatureInstructionInterface $instruction, $jwt_payload, array $additional_header)
    {
        $protected_header = array_merge($instruction->getProtectedHeader(), $additional_header);
        $unprotected_header = $instruction->getUnprotectedHeader();
        $complete_header = array_merge($protected_header, $protected_header);

        $jwt_protected_header = empty($protected_header) ? null : Base64Url::encode(json_encode($protected_header));

        $signature_algorithm = $this->getSignatureAlgorithm($complete_header, $instruction->getKey());

        if (!$this->checkKeyUsage($instruction->getKey(), 'signature')) {
            throw new \InvalidArgumentException('Key cannot be used to sign');
        }

        $signature = $signature_algorithm->sign($instruction->getKey(), $jwt_protected_header.'.'.$jwt_payload);

        $jwt_signature = Base64Url::encode($signature);

        $result = [
            'signature' => $jwt_signature,
        ];
        if (null !== $protected_header) {
            $result['protected'] = $jwt_protected_header;
        }
        if (!empty($unprotected_header)) {
            $result['header'] = $unprotected_header;
        }

        return $result;
    }

    /**
     * @param array                     $complete_header The complete header
     * @param \Jose\Object\JWKInterface $key
     *
     * @return \Jose\Algorithm\Signature\SignatureInterface
     */
    protected function getSignatureAlgorithm(array $complete_header, JWKInterface $key)
    {
        if (!array_key_exists('alg', $complete_header)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if ($key->has('alg') && $key->get('alg') !== $complete_header['alg']) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is allowed with this key.', $complete_header['alg']));
        }

        $signature_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
        if (!$signature_algorithm instanceof SignatureInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $complete_header['alg']));
        }

        return $signature_algorithm;
    }

    /**
     * @param array $instructions
     * @param       $serialization
     *
     * @throws \InvalidArgumentException
     */
    protected function checkInstructions(array $instructions, $serialization)
    {
        if (empty($instructions)) {
            throw new \InvalidArgumentException('No instruction.');
        }
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof SignatureInstructionInterface) {
                throw new \InvalidArgumentException('Bad instruction. Must implement SignatureInstructionInterface.');
            }
            if (!empty($instruction->getUnprotectedHeader()) && JSONSerializationModes::JSON_COMPACT_SERIALIZATION === $serialization) {
                throw new \InvalidArgumentException('Cannot create Compact Json Serialization representation: unprotected header cannot be kept');
            }
        }
    }
}
