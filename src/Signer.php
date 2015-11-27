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
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasJWTManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasPayloadConverter;
use Jose\Operation\SignatureInterface;
use Jose\Payload\PayloadConverterManagerInterface;
use Jose\Util\Converter;

/**
 */
class Signer implements SignerInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasJWTManager;
    use HasPayloadConverter;

    /**
     * Signer constructor.
     *
     * @param \Jose\JWTManagerInterface                      $jwt_manager
     * @param \Jose\JWAManagerInterface                      $jwa_manager
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter_manager
     */
    public function __construct(
        JWTManagerInterface $jwt_manager,
        JWAManagerInterface $jwa_manager,
        PayloadConverterManagerInterface $payload_converter_manager
    )
    {
        $this->setJWTManager($jwt_manager);
        $this->setJWAManager($jwa_manager);
        $this->setPayloadConverter($payload_converter_manager);
    }

    /**
     * @param $input
     */
    private function checkInput(&$input)
    {
        if ($input instanceof JWTInterface) {
            return;
        }

        $header = [];
        $payload = $this->getPayloadConverter()->convertPayloadToString($header, $input);

        $jwt = $this->getJWTManager()->createJWT();
        $jwt = $jwt->withPayload($payload);
        $jwt = $jwt->withProtectedHeader($header);
        $input = $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function sign($input, array $instructions, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $detached_signature = false, &$detached_payload = null)
    {
        $this->checkInput($input);
        $this->checkInstructions($instructions, $serialization);

        $jwt_payload = Base64Url::encode($input->getPayload());

        $signatures = [
            'payload'    => $jwt_payload,
            'signatures' => [],
        ];

        foreach ($instructions as $instruction) {
            $signatures['signatures'][] = $this->computeSignature($instruction, $input, $jwt_payload);
        }

        if (true === $detached_signature) {
            $detached_payload = $signatures['payload'];
            unset($signatures['payload']);
        }

        $prepared = Converter::convert($signatures, $serialization);

        return is_array($prepared) ? current($prepared) : $prepared;
    }

    /**
     * @param \Jose\SignatureInstructionInterface $instruction
     * @param \Jose\JWTInterface                  $input
     * @param string                              $jwt_payload
     *
     * @return array
     */
    protected function computeSignature(SignatureInstructionInterface $instruction, JWTInterface $input, $jwt_payload)
    {
        $protected_header = array_merge($input->getProtectedHeader(), $instruction->getProtectedHeader());
        $unprotected_header = array_merge($input->getUnprotectedHeader(), $instruction->getUnprotectedHeader());
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
     * @param array              $complete_header The complete header
     * @param \Jose\JWKInterface $key
     *
     * @return \Jose\Operation\SignatureInterface
     */
    protected function getSignatureAlgorithm(array $complete_header, JWKInterface $key)
    {
        if (!array_key_exists('alg', $complete_header)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if (null !== $key->getAlgorithm() && $key->getAlgorithm() !== $complete_header['alg']) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is allowed with this key.', $complete_header['alg']));
        }

        $signature_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
        if (!$signature_algorithm instanceof SignatureInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $complete_header['alg']));
        }

        return $signature_algorithm;
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param string                                 $serialization
     */
    protected function checkInstructions(array $instructions, $serialization)
    {
        if (empty($instructions)) {
            throw new \InvalidArgumentException('No instruction.');
        }
        if (count($instructions) > 1 && JSONSerializationModes::JSON_SERIALIZATION !== $serialization) {
            throw new \InvalidArgumentException('Only one instruction authorized when Compact or Flattened Serialization Overview is selected.');
        }
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof SignatureInstructionInterface) {
                throw new \InvalidArgumentException('Bad instruction. Must implement SignatureInstructionInterface.');
            }
        }
    }
}
