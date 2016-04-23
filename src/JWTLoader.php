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
use Jose\Checker\CheckerManagerInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Psr\Log\LoggerInterface;

final class JWTLoader
{
    /**
     * @var \Jose\LoaderInterface
     */
    private $loader;

    /**
     * @var \Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @var \Jose\DecrypterInterface|null
     */
    private $decrypter = null;

    /**
     * @var \Jose\VerifierInterface
     */
    private $verifier;

    /**
     * JWTLoader constructor.
     *
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     * @param \Jose\VerifierInterface               $verifier
     * @param \Psr\Log\LoggerInterface|null         $logger
     */
    public function __construct(CheckerManagerInterface $checker_manager, VerifierInterface $verifier, LoggerInterface $logger = null)
    {
        $this->checker_manager = $checker_manager;
        $this->verifier = $verifier;
        $this->loader = new Loader();
        if (null !== $logger) {
            $this->loader->enableLogging($logger);
        }
    }

    /**
     * @param \Jose\DecrypterInterface $decrypter
     */
    public function enableEncryptionSupport(DecrypterInterface $decrypter)
    {
        $this->decrypter = $decrypter;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->verifier->getSupportedSignatureAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return null === $this->decrypter ? [] : $this->decrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return null === $this->decrypter ? [] : $this->decrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods()
    {
        return null === $this->decrypter ? [] : $this->decrypter->getSupportedCompressionMethods();
    }

    /**
     * @param string                            $assertion
     * @param \Jose\Object\JWKSetInterface|null $encryption_key_set
     * @param bool                              $is_encryption_required
     *
     * @return \Jose\Object\JWSInterface
     */
    public function load($assertion, JWKSetInterface $encryption_key_set = null, $is_encryption_required = false)
    {
        Assertion::string($assertion);
        Assertion::boolean($is_encryption_required);
        $jwt = $this->loader->load($assertion);
        if ($jwt instanceof JWEInterface) {
            Assertion::notNull($encryption_key_set, 'Encryption key set is not available.');
            Assertion::true($this->isEncryptionSupportEnabled(), 'Encryption support is not enabled.');
            Assertion::inArray($jwt->getSharedProtectedHeader('alg'), $this->getSupportedKeyEncryptionAlgorithms(), sprintf('The key encryption algorithm "%s" is not allowed.', $jwt->getSharedProtectedHeader('alg')));
            Assertion::inArray($jwt->getSharedProtectedHeader('enc'), $this->getSupportedContentEncryptionAlgorithms(), sprintf('The content encryption algorithm "%s" is not allowed or not supported.', $jwt->getSharedProtectedHeader('enc')));
            $jwt = $this->decryptAssertion($jwt, $encryption_key_set);
        } elseif (true === $is_encryption_required) {
            throw new \InvalidArgumentException('The assertion must be encrypted.');
        }

        return $jwt;
    }

    /**
     * @return bool
     */
    private function isEncryptionSupportEnabled()
    {
        return null !== $this->decrypter;
    }

    /**
     * @param \Jose\Object\JWEInterface    $jwe
     * @param \Jose\Object\JWKSetInterface $encryption_key_set
     *
     * @return \Jose\Object\JWSInterface
     */
    private function decryptAssertion(JWEInterface $jwe, JWKSetInterface $encryption_key_set)
    {
        $this->decrypter->decryptUsingKeySet($jwe, $encryption_key_set);

        $jws = $this->loader->load($jwe->getPayload());
        Assertion::isInstanceOf($jws, JWSInterface::class, 'The encrypted assertion does not contain a JWS.');

        return $jws;
    }

    /**
     * @param \Jose\Object\JWSInterface    $jws
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     */
    public function verifySignature(JWSInterface $jws, JWKSetInterface $signature_key_set)
    {
        Assertion::inArray($jws->getSignature(0)->getProtectedHeader('alg'), $this->getSupportedSignatureAlgorithms(), sprintf('The signature algorithm "%s" is not supported or not allowed.', $jws->getSignature(0)->getProtectedHeader('alg')));

        $index = null;
        $this->verifier->verifyWithKeySet($jws, $signature_key_set, null, $index);
        $this->checker_manager->checkJWS($jws, $index);
    }
}
