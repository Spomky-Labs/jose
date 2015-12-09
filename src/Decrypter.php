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

use Jose\Algorithm\ContentEncryption\ContentEncryptionInterface;
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Behaviour\HasCheckerManager;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasJWKFinderManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasPayloadConverter;
use Jose\Checker\CheckerManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use Jose\Finder\JWKFinderManagerInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Payload\PayloadConverterManagerInterface;

/**
 */
final class Decrypter implements DecrypterInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasJWKFinderManager;
    use HasCheckerManager;
    use HasPayloadConverter;
    use HasCompressionManager;

    /**
     * Loader constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface                      $jwa_manager
     * @param \Jose\Finder\JWKFinderManagerInterface                $jwk_finder_manager
     * @param \Jose\Payload\PayloadConverterManagerInterface $payload_converter_manager
     * @param \Jose\Compression\CompressionManagerInterface  $compression_manager
     * @param \Jose\Checker\CheckerManagerInterface          $checker_manager
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        JWKFinderManagerInterface $jwk_finder_manager,
        PayloadConverterManagerInterface $payload_converter_manager,
        CompressionManagerInterface $compression_manager,
        CheckerManagerInterface $checker_manager)
    {
        $this->setJWAManager($jwa_manager);
        $this->setJWKFinderManager($jwk_finder_manager);
        $this->setPayloadConverter($payload_converter_manager);
        $this->setCompressionManager($compression_manager);
        $this->setCheckerManager($checker_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(JWEInterface &$jwe, JWKSetInterface $jwk_set = null)
    {
        //$complete_header = $jwe->getHeaders();

        $this->checkCompleteHeader($jwe->getHeaders());

        if (null === $jwk_set) {
            $jwk_set = $this->getKeysFromCompleteHeader(
                $jwe->getHeaders(),
                JWKFinderManagerInterface::KEY_TYPE_PRIVATE | JWKFinderManagerInterface::KEY_TYPE_DIRECT | JWKFinderManagerInterface::KEY_TYPE_SYMMETRIC
            );
        }
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($jwe->getHeader('alg'));
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($jwe->getHeader('enc'));

        foreach ($jwk_set as $jwk) {
            if (!$this->checkKeyUsage($jwk, 'decryption')) {
                continue;
            }
            if (!$this->checkKeyAlgorithm($jwk, $key_encryption_algorithm->getAlgorithmName())) {
                continue;
            }
            try {
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $jwe->getEncryptedKey(), $jwe->getHeaders());

                if (null !== $cek) {
                    if (true === $this->decryptPayload($jwe, $cek, $content_encryption_algorithm)) {
                        $this->getCheckerManager()->checkJWT($jwe);
                        return true;
                    }
                }
            } catch (\InvalidArgumentException $e) {
                //We do nothing, we continue with other keys
            }
        }

        return false;
    }

    /**
     * @param \Jose\Algorithm\JWAInterface                                           $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryption\ContentEncryptionInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                                           $key
     * @param string|null                                                  $encrypted_cek
     * @param array                                                        $header
     *
     * @return string|null
     */
    private function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionInterface $content_encryption_algorithm, JWKInterface $key, $encrypted_cek, array $header)
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key, $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $key, null, $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $encrypted_cek, $content_encryption_algorithm->getCEKSize(), $header);
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey($key, $encrypted_cek, $header);
        } else {
            throw new \RuntimeException('Unsupported CEK generation');
        }
    }

    /**
     * @param \Jose\Object\JWEInterface                                           $jwe
     * @param string                                                       $cek
     * @param \Jose\Algorithm\ContentEncryption\ContentEncryptionInterface $content_encryption_algorithm
     *
     * @return \Jose\Object\JWEInterface
     */
    private function decryptPayload(JWEInterface &$jwe, $cek, $content_encryption_algorithm)
    {
        $payload = $content_encryption_algorithm->decryptContent(
            $jwe->getCiphertext(),
            $cek,
            $jwe->getIV(),
            $jwe->getAAD(),
            $jwe->getEncodedProtectedHeaders(),
            $jwe->getTag()
        );

        if (null === $payload) {
            return false;
        }

        if ($jwe->hasHeader('zip')) {
            $compression_method = $this->getCompressionMethod($jwe->getHeader('zip'));
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                throw new \RuntimeException('Decompression failed');
            }
        }

        $payload = $this->getPayloadConverter()->convertStringToPayload($jwe->getHeaders(), $payload);

        $jwe = $jwe->withPayload($payload);

        return true;
    }

    /**
     * @param array $complete_header
     *
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $complete_header)
    {
        foreach (['enc', 'alg'] as $key) {
            if (!array_key_exists($key, $complete_header)) {
                throw new \InvalidArgumentException(sprintf("Parameters '%s' is missing.", $key));
            }
        }
    }

    /**
     * @param string $algorithm
     *
     * @return \Jose\Algorithm\KeyEncryption\DirectEncryptionInterface|\Jose\Algorithm\KeyEncryption\KeyEncryptionInterface|\Jose\Algorithm\KeyEncryption\KeyAgreementInterface|\Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface
     */
    private function getKeyEncryptionAlgorithm($algorithm)
    {
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        foreach ([
                     '\Jose\Algorithm\KeyEncryption\DirectEncryptionInterface',
                     '\Jose\Algorithm\KeyEncryption\KeyEncryptionInterface',
                     '\Jose\Algorithm\KeyEncryption\KeyAgreementInterface',
                     '\Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface',
                 ] as $class) {
            if ($key_encryption_algorithm instanceof $class) {
                return $key_encryption_algorithm;
            }
        }
        throw new \RuntimeException(sprintf("The key encryption algorithm '%s' is not supported or not a key encryption algorithm instance.", $algorithm));
    }

    /**
     * @param $algorithm
     *
     * @return \Jose\Algorithm\ContentEncryption\ContentEncryptionInterface
     */
    private function getContentEncryptionAlgorithm($algorithm)
    {
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
            throw new \RuntimeException("The algorithm '".$algorithm."' does not implement ContentEncryptionInterface.");
        }

        return $content_encryption_algorithm;
    }

    /**
     * @param string $method
     *
     * @throws \InvalidArgumentException
     *
     * @return \Jose\Compression\CompressionInterface
     */
    private function getCompressionMethod($method)
    {
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        if (null === $compression_method) {
            throw new \InvalidArgumentException(sprintf("Compression method '%s' not supported"), $method);
        }

        return $compression_method;
    }

    /**
     * @param array $header
     * @param int   $key_type
     *
     * @return \Jose\Object\JWKSetInterface
     */
    private function getKeysFromCompleteHeader(array $header, $key_type)
    {
        $keys = $this->getJWKFinderManager()->findJWK($header, $key_type);
        $jwkset = new JWKSet($keys);

        return $jwkset;
    }
}
