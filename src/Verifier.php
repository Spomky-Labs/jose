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
use Jose\Behaviour\HasCheckerManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Checker\CheckerManagerInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\SignatureInterface;

/**
 */
final class Verifier implements VerifierInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCheckerManager;

    /**
     * Loader constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface   $jwa_manager
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        CheckerManagerInterface $checker_manager)
    {
        $this->setJWAManager($jwa_manager);
        $this->setCheckerManager($checker_manager);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     */
    public function verifyWithKey(JWSInterface $jws, JWKInterface $jwk, $detached_payload = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey($jwk);

        return $this->verifyWithKeySet($jws, $jwk_set, $detached_payload);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     */
    public function verifyWithKeySet(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null)
    {
        if (null !== $detached_payload && !empty($jws->getEncodedPayload())) {
            throw new \InvalidArgumentException('A detached payload is set, but the JWS already has a payload.');
        }
        if (0 === count($jwk_set)) {
            throw new \InvalidArgumentException('No key in the key set.');
        }
        foreach ($jws->getSignatures() as $signature) {
            $input = $signature->getEncodedProtectedHeaders().'.'.(null === $detached_payload ? $jws->getEncodedPayload() : $detached_payload);

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
        }

        return false;
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return \Jose\Algorithm\SignatureAlgorithmInterface|null
     */
    private function getAlgorithm(SignatureInterface $signature)
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        if (!array_key_exists('alg', $complete_headers)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }

        $algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        if (!$algorithm instanceof SignatureAlgorithmInterface) {
            throw new \RuntimeException(sprintf('The algorithm "%s" is not supported or does not implement SignatureInterface.', $complete_headers['alg']));
        }

        return $algorithm;
    }
}
