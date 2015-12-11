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

use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\Signature\SignatureInterface;
use Jose\Behaviour\HasCheckerManager;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasPayloadConverter;
use Jose\Checker\CheckerManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Payload\PayloadConverterManagerInterface;

/**
 */
final class Verifier implements VerifierInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCheckerManager;
    use HasPayloadConverter;
    use HasCompressionManager;

    /**
     * Loader constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface            $jwa_manager
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter_manager
     * @param \Jose\Compression\CompressionManagerInterface  $compression_manager
     * @param \Jose\Checker\CheckerManagerInterface          $checker_manager
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        PayloadConverterManagerInterface $payload_converter_manager,
        CompressionManagerInterface $compression_manager,
        CheckerManagerInterface $checker_manager)
    {
        $this->setJWAManager($jwa_manager);
        $this->setPayloadConverter($payload_converter_manager);
        $this->setCompressionManager($compression_manager);
        $this->setCheckerManager($checker_manager);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     */
    public function verify(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null)
    {
        if (null !== $detached_payload && !empty($jws->getPayload())) {
            throw new \InvalidArgumentException('A detached payload is set, but the JWS already has a payload');
        }
        $input = $jws->getEncodedProtectedHeader().'.'.(null === $detached_payload ? $jws->getEncodedPayload() : $detached_payload);

        if (0 === count($jwk_set)) {
            return false;
        }
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($jws->getHeaders());
            if (!$this->checkKeyUsage($jwk, 'verification')) {
                continue;
            }
            if (!$this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName())) {
                continue;
            }
            try {
                if (true === $algorithm->verify($jwk, $input, $jws->getSignature())) {
                    $this->getCheckerManager()->checkJWT($jws);

                    return true;
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
            }
        }

        return false;
    }

    /**
     * @param array $header
     *
     * @return \Jose\Algorithm\Signature\SignatureInterface|null
     */
    private function getAlgorithm(array $header)
    {
        if (!array_key_exists('alg', $header)) {
            throw new \InvalidArgumentException("No 'alg' parameter set in the header.");
        }
        $alg = $header['alg'];

        $algorithm = $this->getJWAManager()->getAlgorithm($alg);
        if (!$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException(sprintf('The algorithm "$alg" is not supported or does not implement SignatureInterface.', $alg));
        }

        return $algorithm;
    }
}
