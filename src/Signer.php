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
use Jose\Object\Signature;
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
    public function addSignatureWithDetachedPayload(JWSInterface &$jws, JWKInterface $key, $detached_payload, array $protected_headers = [], array $headers = [])
    {
        $this->log(LogLevel::INFO, 'Trying to add a signature to the JWS object with detached payload', ['jws' => $jws, 'key' => $key, 'payload' => $detached_payload, 'protected' => $protected_headers, 'header' => $headers]);
        $signature = $this->createSignature($key, $detached_payload, $protected_headers, $headers);

        $jws = $jws->addSignature($signature);
        $this->log(LogLevel::INFO, 'Signature added');
    }

    /**
     * {@inheritdoc}
     */
    public function addSignature(JWSInterface &$jws, JWKInterface $key, array $protected_headers = [], array $headers = [])
    {
        $this->log(LogLevel::INFO, 'Trying to add a signature to the JWS object', ['jws' => $jws, 'key' => $key, 'protected' => $protected_headers, 'header' => $headers]);
        if (null === $jws->getEncodedPayload()) {
            throw new \InvalidArgumentException('No payload.');
        }
        $signature = $this->createSignature($key, $jws->getEncodedPayload(), $protected_headers, $headers);

        $jws = $jws->addSignature($signature);
        $this->log(LogLevel::INFO, 'Signature added');
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $payload
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\Signature|\Jose\Object\SignatureInterface
     */
    private function createSignature(JWKInterface $key, $payload, array $protected_headers, array $headers)
    {
        $this->log(LogLevel::DEBUG, 'Creation of the signature');
        $this->checkKeyUsage($key, 'signature');
        $signature = new Signature();
        if (!empty($protected_headers)) {
            $this->log(LogLevel::DEBUG, 'The signature has of a protected header', ['protected' => $protected_headers]);
            $signature = $signature->withProtectedHeaders($protected_headers);
        }
        if (!empty($headers)) {
            $this->log(LogLevel::DEBUG, 'The signature has of a header', ['header' => $headers]);
            $signature = $signature->withHeaders($headers);
        }

        $signature_algorithm = $this->getSignatureAlgorithm($signature->getAllHeaders(), $key);

        $this->log(LogLevel::DEBUG, 'Trying to compute the signature');
        $value = $signature_algorithm->sign($key, $signature->getEncodedProtectedHeaders().'.'.$payload);
        $this->log(LogLevel::DEBUG, 'Signature computation done');

        $signature = $signature->withSignature($value);

        $this->log(LogLevel::DEBUG, 'The signature is done', ['signature' => $signature]);

        return $signature;
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
