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
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Behaviour\CommonSigningMethods;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasLogger;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWSInterface;
use Jose\Object\Signature;
use Jose\Object\SignatureInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class Signer implements SignerInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasLogger;
    use CommonSigningMethods;

    /**
     * Signer constructor.
     *
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $signature_algorithms
     */
    public function __construct(array $signature_algorithms)
    {
        $this->setSignatureAlgorithms($signature_algorithms);

        $this->setJWAManager(AlgorithmManagerFactory::createAlgorithmManager($signature_algorithms));
    }

    /**
     * {@inheritdoc}
     */
    public static function createSigner(array $signature_algorithms, LoggerInterface $logger = null)
    {
        $signer = new self($signature_algorithms);
        if (null !== $logger) {
            $signer->enableLogging($logger);
        }
        
        return $signer;
    }

    /**
     * {@inheritdoc}
     */
    public function signWithDetachedPayload(JWSInterface &$jws, $detached_payload)
    {
        $this->log(LogLevel::INFO, 'Trying to sign the JWS object with detached payload', ['jws' => $jws, 'payload' => $detached_payload]);
        $nb_signatures = $jws->countSignatures();
        
        for ($i = 0; $i < $nb_signatures; $i++) {
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
        Assertion::notNull($jws->getEncodedPayload(), 'No payload.');
        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $this->computeSignature($jws->getEncodedPayload(), $jws->getSignature($i));
        }
        $this->log(LogLevel::INFO, 'JWS object signed!');
    }

    /**
     * @param string                          $payload
     * @param \Jose\Object\SignatureInterface $signature
     */
    private function computeSignature($payload, SignatureInterface &$signature)
    {
        $this->log(LogLevel::DEBUG, 'Creation of the signature');
        if (null === $signature->getSignatureKey()) {
            $this->log(LogLevel::DEBUG, 'The signature key is not set. Aborting.');
            return;
        }
        $this->checkKeyUsage($signature->getSignatureKey(), 'signature');

        $signature_algorithm = $this->getSignatureAlgorithm($signature->getAllHeaders(), $signature->getSignatureKey());

        $this->log(LogLevel::DEBUG, 'Trying to compute the signature');
        $value = $signature_algorithm->sign($signature->getSignatureKey(), $signature->getEncodedProtectedHeaders().'.'.$payload);
        $this->log(LogLevel::DEBUG, 'Signature computation done');

        $signature = Signature::createSignatureFromLoadedData(
            $value,
            $signature->getEncodedProtectedHeaders(),
            $signature->getHeaders()
        );

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
        Assertion::keyExists($complete_header, 'alg', 'No "alg" parameter set in the header.');

        $this->log(LogLevel::DEBUG, 'The algorithm is {alg}', ['alg' => $complete_header['alg']]);

        Assertion::false(
            $key->has('alg') && $key->get('alg') !== $complete_header['alg'],
            sprintf('The algorithm "%s" is not allowed with this key.', $complete_header['alg'])
        );

        $signature_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
        Assertion::isInstanceOf($signature_algorithm, SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported.', $complete_header['alg']));

        $this->log(LogLevel::DEBUG, 'The algorithm {alg} is supported', ['alg' => $complete_header['alg'], 'handler' => $signature_algorithm]);

        return $signature_algorithm;
    }
}
