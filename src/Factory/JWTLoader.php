<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Checker\CheckerManagerInterface;
use Jose\Decrypter;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Verifier;
use Psr\Log\LoggerInterface;

final class JWTLoader
{
    /**
     * @var null|\Psr\Log\LoggerInterface
     */
    private $logger;

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
     * @param \Jose\Checker\CheckerManagerInterface                  $checker_manager
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $supported_signature_algorithms
     * @param \Psr\Log\LoggerInterface|null                          $logger
     */
    public function __construct(CheckerManagerInterface $checker_manager, array $supported_signature_algorithms, LoggerInterface $logger = null)
    {
        Assertion::notEmpty($supported_signature_algorithms, 'At least one signature algorithm must be set.');
        
        $this->checker_manager = $checker_manager;
        $this->logger = $logger;
        $this->loader = new Loader();
        if (null !== $logger) {
            $this->loader->enableLogging($logger);
        }
        $this->verifier = Verifier::createVerifier($supported_signature_algorithms, $logger);
    }

    /**
     * @param string[]|\Jose\Algorithm\KeyEncryptionAlgorithmInterface[]     $supported_key_encryption_algorithms
     * @param string[]|\Jose\Algorithm\ContentEncryptionAlgorithmInterface[] $supported_content_encryption_algorithms
     * @param string[]|\Jose\Compression\CompressionInterface                $supported_compression_methods
     */
    public function enableEncryptionSupport(array $supported_key_encryption_algorithms,
                                            array $supported_content_encryption_algorithms,
                                            array $supported_compression_methods = ['DEF', 'ZLIB', 'GZ']
    ) {
        Assertion::notEmpty($supported_key_encryption_algorithms, 'At least one key encryption algorithm must be set.');
        Assertion::notEmpty($supported_content_encryption_algorithms, 'At least one content encryption algorithm must be set.');

        $this->decrypter = Decrypter::createDecrypter(
            $supported_key_encryption_algorithms,
            $supported_content_encryption_algorithms,
            $supported_compression_methods,
            $this->logger
        );
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
     * @param array                             $allowed_key_encryption_algorithms
     * @param array                             $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface|null $encryption_key_set
     * @param bool                              $is_encryption_required
     *
     * @return \Jose\Object\JWSInterface
     */
    public function load($assertion, array $allowed_key_encryption_algorithms = [], array $allowed_content_encryption_algorithms = [], JWKSetInterface $encryption_key_set = null, $is_encryption_required = false)
    {
        Assertion::string($assertion);
        Assertion::boolean($is_encryption_required);
        $jwt = $this->loader->load($assertion);
        if ($jwt instanceof JWEInterface) {
            Assertion::notNull($encryption_key_set, 'Encryption key set is not available.');
            Assertion::true($this->isEncryptionSupportEnabled(), 'Encryption support is not enabled.');
            $key_encryption_algorithms = array_intersect($allowed_key_encryption_algorithms, $this->getSupportedKeyEncryptionAlgorithms());
            $content_encryption_algorithms = array_intersect($allowed_content_encryption_algorithms, $this->getSupportedContentEncryptionAlgorithms());
            Assertion::inArray($jwt->getSharedProtectedHeader('alg'), $key_encryption_algorithms, sprintf('The key encryption algorithm "%s" is not allowed.', $jwt->getSharedProtectedHeader('alg')));
            Assertion::inArray($jwt->getSharedProtectedHeader('enc'), $content_encryption_algorithms, sprintf('The content encryption algorithm "%s" is not allowed or not supported.', $jwt->getSharedProtectedHeader('enc')));
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
     * @param array                        $allowed_signature_algorithms
     */
    public function verifySignature(JWSInterface $jws, JWKSetInterface $signature_key_set, array $allowed_signature_algorithms)
    {
        $algorithms = array_intersect(
            $allowed_signature_algorithms,
            $this->getSupportedSignatureAlgorithms()
        );
        Assertion::inArray($jws->getSignature(0)->getProtectedHeader('alg'), $algorithms, sprintf('The signature algorithm "%s" is not supported or not allowed.', $jws->getSignature(0)->getProtectedHeader('alg')));

        $index = null;
        $this->verifier->verifyWithKeySet($jws, $signature_key_set, null, $index);
        $this->checker_manager->checkJWS($jws, $index);
    }
}
