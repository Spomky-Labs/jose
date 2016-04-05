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
use Jose\Encrypter;
use Jose\Object\JWKInterface;
use Jose\Signer;
use Psr\Log\LoggerInterface;

final class JWTCreator
{
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var \Jose\EncrypterInterface|null
     */
    private $encrypter = null;

    /**
     * @var \Jose\SignerInterface
     */
    private $signer;

    /**
     * JWTCreator constructor.
     *
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $supported_signature_algorithms
     * @param \Psr\Log\LoggerInterface|null                          $logger
     */
    public function __construct(array $supported_signature_algorithms, LoggerInterface $logger = null)
    {
        Assertion::notEmpty($supported_signature_algorithms, $logger);

        $this->logger = $logger;
        $this->signer = Signer::createSigner($supported_signature_algorithms, $logger);
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

        $this->encrypter = Encrypter::createEncrypter(
            $supported_key_encryption_algorithms,
            $supported_content_encryption_algorithms,
            $supported_compression_methods,
            $this->logger
        );
    }

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param \Jose\Object\JWKInterface $signature_key
     *
     * @return string
     */
    public function sign($payload, array $signature_protected_headers, JWKInterface $signature_key)
    {
        $jws = JWSFactory::createJWS($payload);

        $jws = $jws->addSignature($signature_key, $signature_protected_headers);
        $this->signer->sign($jws);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param string                    $payload
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    public function encrypt($payload, array $encryption_protected_headers, JWKInterface $encryption_key)
    {
        Assertion::notNull($this->encrypter, 'The encryption support is not enabled');

        $jwe = JWEFactory::createJWE($payload, $encryption_protected_headers);
        $jwe = $jwe->addRecipient($encryption_key);
        $this->encrypter->encrypt($jwe);

        return $jwe->toCompactJSON(0);
    }

    /**
     * @return string[]
     */
    public function getSignatureAlgorithms()
    {
        return $this->signer->getSupportedSignatureAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return null === $this->encrypter ? [] : $this->encrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return null === $this->encrypter ? [] : $this->encrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods()
    {
        return null === $this->encrypter ? [] : $this->encrypter->getSupportedCompressionMethods();
    }
}
