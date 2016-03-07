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

use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasLogger;
use Jose\Object\JWKInterface;
use Jose\Object\JWSInterface;
use Jose\Object\SignatureInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 */
final class Signer implements SignerInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasLogger;

    /**
     * Signer constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface $jwa_manager
     * @param \Psr\Log\LoggerInterface|null       $logger
     */
    public function __construct(JWAManagerInterface $jwa_manager,
                                LoggerInterface $logger = null
    ) {
        $this->setJWAManager($jwa_manager);

        if (null !== $logger) {
            $this->setLogger($logger);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function signWithDetachedPayload(JWSInterface &$jws, $detached_payload)
    {
        $this->log(LogLevel::INFO, 'Trying to sign the JWS object with detached payload', ['jws' => $jws, 'payload' => $detached_payload]);

        for ($i = 0; $i < $jws->countSignatures(); $i++) {
            $this->computeSignature($detached_payload, $jws->getSignature($i));
        }

        $this->log(LogLevel::INFO, 'Signature added');
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWSInterface &$jws)
    {
        $this->log(LogLevel::INFO, 'Trying to sign the JWS object', ['jws' => $jws]);
        if (null === $jws->getEncodedPayload()) {
            throw new \InvalidArgumentException('No payload.');
        }
        for ($i = 0; $i < $jws->countSignatures(); $i++) {
            $this->computeSignature($jws->getEncodedPayload(), $jws->getSignature($i));
        }
        $this->log(LogLevel::INFO, 'Signature added');
    }

    /**
     * @param string                          $payload
     * @param \Jose\Object\SignatureInterface $signature
     */
    private function computeSignature($payload, SignatureInterface &$signature)
    {
        $this->log(LogLevel::DEBUG, 'Creation of the signature');
        $this->checkKeyUsage($signature->getSignatureKey(), 'signature');

        $signature_algorithm = $this->getSignatureAlgorithm($signature->getAllHeaders(), $signature->getSignatureKey());

        $this->log(LogLevel::DEBUG, 'Trying to compute the signature');
        $value = $signature_algorithm->sign($signature->getSignatureKey(), $signature->getEncodedProtectedHeaders().'.'.$payload);
        $this->log(LogLevel::DEBUG, 'Signature computation done');

        $signature = $signature->withSignature($value);

        $this->log(LogLevel::DEBUG, 'The signature is done', ['signature' => $signature]);
    }

    /**
     * @param array                     $complete_header The complete header
     * @param \Jose\Object\JWKInterface $key
     *
     * @return \Jose\Algorithm\SignatureAlgorithmInterface
     */
    private function getSignatureAlgorithm(array $complete_header, JWKInterface $key)
    {
        $this->log(LogLevel::DEBUG, 'Trying to find the algorithm used to sign');
        if (!array_key_exists('alg', $complete_header)) {
            $this->log(LogLevel::ERROR, 'No "alg" parameter set in the header');
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        $this->log(LogLevel::DEBUG, 'The algorithm is {alg}', ['alg' => $complete_header['alg']]);

        if ($key->has('alg') && $key->get('alg') !== $complete_header['alg']) {
            $this->log(LogLevel::ERROR, 'The algorithm {alg} is allowed with this key', ['alg' => $complete_header['alg']]);
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is allowed with this key.', $complete_header['alg']));
        }

        $signature_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
        if (!$signature_algorithm instanceof SignatureAlgorithmInterface) {
            $this->log(LogLevel::ERROR, 'The algorithm {alg} is not supported', ['alg' => $complete_header['alg']]);
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $complete_header['alg']));
        }

        $this->log(LogLevel::DEBUG, 'The algorithm {alg} is supported', ['alg' => $complete_header['alg'], 'handler' => $signature_algorithm]);

        return $signature_algorithm;
    }
}
