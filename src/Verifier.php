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
use Base64Url\Base64Url;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Behaviour\CommonSigningMethods;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasLogger;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\SignatureInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class Verifier implements VerifierInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasLogger;
    use CommonSigningMethods;

    /**
     * Verifier constructor.
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
    public static function createVerifier(array $signature_algorithms, LoggerInterface $logger = null)
    {
        $verifier = new self($signature_algorithms);
        if (null !== $logger) {
            $verifier->enableLogging($logger);
        }

        return $verifier;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     */
    public function verifyWithKey(JWSInterface $jws, JWKInterface $jwk, $detached_payload = null, &$recipient_index = null)
    {
        $this->log(LogLevel::DEBUG, 'Trying to verify the JWS with the key', ['jws' => $jws, 'jwk' => $jwk, 'detached_payload' => $detached_payload]);
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyWithKeySet(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->log(LogLevel::DEBUG, 'Trying to verify the JWS with the key set', ['jwk' => $jws, 'jwk_set' => $jwk_set, 'detached_payload' => $detached_payload]);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * @param \Jose\Object\JWSInterface       $jws
     * @param \Jose\Object\JWKSetInterface    $jwk_set
     * @param \Jose\Object\SignatureInterface $signature
     * @param string|null                     $detached_payload
     *
     * @return bool
     */
    private function verifySignature(JWSInterface $jws, JWKSetInterface $jwk_set, SignatureInterface $signature, $detached_payload = null)
    {
        $input = $this->getInputToVerify($jws, $signature, $detached_payload);

        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);
            try {
                $this->checkKeyUsage($jwk, 'verification');
                $this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName());
                if (true === $algorithm->verify($jwk, $input, $signature->getSignature())) {
                    return true;
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return false;
    }

    /**
     * @param \Jose\Object\JWSInterface       $jws
     * @param \Jose\Object\SignatureInterface $signature
     * @param string|null                     $detached_payload
     *
     * @return string
     */
    private function getInputToVerify(JWSInterface $jws, SignatureInterface $signature, $detached_payload)
    {
        $encoded_protected_headers = $signature->getEncodedProtectedHeaders();
        $payload = empty($jws->getPayload()) ? $detached_payload : $jws->getPayload();
        $payload = is_string($payload) ? $payload : json_encode($payload);
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            $encoded_payload = Base64Url::encode($payload);

            return sprintf('%s.%s', $encoded_protected_headers, $encoded_payload);
        }

        return sprintf('%s.%s', $encoded_protected_headers, $payload);
    }

    /**
     * @param \Jose\Object\JWSInterface    $jws
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param string|null                  $detached_payload
     * @param int|null                     $recipient_index
     */
    private function verifySignatures(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->checkPayload($jws, $detached_payload);
        $this->checkJWKSet($jwk_set);
        $this->checkSignatures($jws);

        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $signature = $jws->getSignature($i);
            $result = $this->verifySignature($jws, $jwk_set, $signature, $detached_payload);

            if (true === $result) {
                $recipient_index = $i;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to verify the JWS.');
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    private function checkSignatures(JWSInterface $jws)
    {
        Assertion::greaterThan($jws->countSignatures(), 0, 'The JWS does not contain any signature.');
        $this->log(LogLevel::INFO, 'The JWS contains {nb} signature(s)', ['nb' => $jws->countSignatures()]);
    }

    /**
     * @param \Jose\Object\JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan($jwk_set->countKeys(), 0, 'There is no key in the key set.');
        $this->log(LogLevel::INFO, 'The JWK Set contains {nb} key(s)', ['nb' => count($jwk_set)]);
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param null|string               $detached_payload
     */
    private function checkPayload(JWSInterface $jws, $detached_payload = null)
    {
        Assertion::false(
            null !== $detached_payload && !empty($jws->getPayload()),
            'A detached payload is set, but the JWS already has a payload.'
        );
        Assertion::true(
            !empty($jws->getPayload()) || null !== $detached_payload,
            'No payload.'
        );
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return \Jose\Algorithm\SignatureAlgorithmInterface
     */
    private function getAlgorithm(SignatureInterface $signature)
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header.');

        $algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($algorithm, SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported or does not implement SignatureInterface.', $complete_headers['alg']));

        return $algorithm;
    }
}
