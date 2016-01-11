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
use Jose\Algorithm\Signature\SignatureInterface;
use Jose\Behaviour\HasCheckerManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Checker\CheckerManagerInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;

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
    public function verify(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null)
    {
        if (null !== $detached_payload && !empty($jws->getEncodedPayload())) {
            throw new \InvalidArgumentException('A detached payload is set, but the JWS already has a payload');
        }
        $input = $jws->getEncodedProtectedHeader().'.'.(null === $detached_payload ? $jws->getEncodedPayload() : $detached_payload);

        if (0 === count($jwk_set)) {
            return false;
        }
        $verified = false;
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($jws);
            if (!$this->checkKeyUsage($jwk, 'verification')) {
                continue;
            }
            if (!$this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName())) {
                continue;
            }
            try {
                $verified = $algorithm->verify($jwk, $input, $jws->getSignature());
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
            if (true === $verified) {
                $this->getCheckerManager()->checkJWT($jws);

                return true;
            }
        }

        return false;
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     *
     * @return \Jose\Algorithm\Signature\SignatureInterface
     */
    private function getAlgorithm(JWSInterface $jws)
    {
        if (!$jws->hasHeader('alg')) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        $alg = $jws->getHeader('alg');

        $algorithm = $this->getJWAManager()->getAlgorithm($alg);
        if (!$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException(sprintf('The algorithm "%s" is not supported or does not implement SignatureInterface.', $alg));
        }

        return $algorithm;
    }
}
