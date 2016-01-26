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

use Base64Url\Base64Url;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Compression\CompressionManagerInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\Recipient;

/**
 */
final class Encrypter implements EncrypterInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCompressionManager;

    /**
     * Encrypter constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface           $jwa_manager
     * @param \Jose\Compression\CompressionManagerInterface $compression_manager
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        CompressionManagerInterface $compression_manager)
    {
        $this->setJWAManager($jwa_manager);
        $this->setCompressionManager($compression_manager);
    }

    /**
     * @param \Jose\Object\JWEInterface      $jwe
     * @param \Jose\Object\JWKInterface      $recipient_key
     * @param \Jose\Object\JWKInterface|null $sender_key
     * @param array                          $recipient_headers
     *
     * @return \Jose\Object\JWEInterface
     */
    public function addRecipient(JWEInterface $jwe, JWKInterface $recipient_key, JWKInterface $sender_key = null, array $recipient_headers = [])
    {
        $complete_headers = array_merge(
            $jwe->getSharedProtectedHeaders(),
            $jwe->getSharedHeaders(),
            $recipient_headers
        );

        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

        // Content Encryption Algorithm
        $content_encryption_algorithm = $this->findContentEncryptionAlgorithm($complete_headers);

        if (null === $jwe->getCiphertext()) {
            // the content is not yet encrypted (no recipient)

            if (!empty($jwe->getSharedProtectedHeaders())) {
                $jwe = $jwe->withEncodedSharedProtectedHeaders(Base64Url::encode(json_encode($jwe->getSharedProtectedHeaders())));
            }

            // CEK
            $content_encryption_key = $this->getCEK(
                $complete_headers,
                $key_encryption_algorithm,
                $content_encryption_algorithm,
                $recipient_key,
                $sender_key
            );
            $jwe = $jwe->withContentEncryptionKey($content_encryption_key);

            // IV
            if (null !== $iv_size = $content_encryption_algorithm->getIVSize()) {
                $iv = $this->createIV($iv_size);
                $jwe = $jwe->withIV($iv);
            }

            // We encrypt the payload and get the tag
            $tag = null;
            $payload = $this->compressPayloadIfNeeded($jwe->getPayload(), $complete_headers);

            $ciphertext = $content_encryption_algorithm->encryptContent(
                $payload,
                $content_encryption_key,
                $jwe->getIV(),
                $jwe->getAAD(),
                $jwe->getEncodedSharedProtectedHeaders(),
                $tag
            );
            $jwe = $jwe->withCiphertext($ciphertext);

            // Tag
            if (null !== $tag) {
                $jwe = $jwe->withTag($tag);
            }
            // JWT Ciphertext
        } else {
            // On vérifie le jey managmenet mode

            // On vérifie si le CEK est disponible.
            // - si dispo on quitte le if
            // - sinon on ne peut pas aller plus loin. Le JWE doit être décrypté avant
        }

        $recipient = new Recipient();
        $recipient = $recipient->withHeaders($recipient_headers);

        $encrypted_content_encryption_key = $this->getEncryptedKey(
            $complete_headers,
            $jwe->getContentEncryptionKey(),
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $recipient_key,
            $sender_key
        );
        if (null !== $encrypted_content_encryption_key) {
            $recipient = $recipient->withEncryptedKey($encrypted_content_encryption_key);
        }
        $jwe = $jwe->addRecipient($recipient);

        return $jwe;
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     *
     * @return string
     */
    private function compressPayloadIfNeeded($payload, array $complete_headers)
    {
        if (!array_key_exists('zip', $complete_headers)) {
            return $payload;
        }

        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($complete_headers['zip']);
        if (null === $compression_method) {
            throw new \RuntimeException(sprintf('Compression method "%s" not supported', $complete_headers['zip']));
        }
        $compressed_payload = $compression_method->compress($payload);
        if (!is_string($compressed_payload)) {
            throw new \RuntimeException('Compression failed.');
        }

        return $compressed_payload;
    }

    private function getEncryptedKey(array $complete_headers, $cek, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->encryptKey(
                    $recipient_key,
                    $cek,
                    $complete_headers
                );
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $key_encryption_algorithm->wrapKey(
                $recipient_key,
                $cek,
                $complete_headers
            );
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            if (!$sender_key instanceof JWKInterface) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            $additional_header_values = [];
            $jwt_cek = $key_encryption_algorithm->wrapAgreementKey($sender_key, $recipient_key, $cek, $content_encryption_algorithm->getCEKSize(), $complete_headers, $additional_header_values);
            //$this->updateHeader($additional_header_values, $protected_header, $recipient_header, $serialization);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            $additional_header_values = [];
            $jwt_cek = $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $sender_key, $recipient_key, $complete_headers, $additional_header_values);
            //$this->updateHeader($additional_header_values, $protected_header, $recipient_header, $serialization);
        }
    }

    private function getCEK(array $complete_headers, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $this->createCEK($content_encryption_algorithm->getCEKSize());
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $this->createCEK($content_encryption_algorithm->getCEKSize());
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $this->calculateAgreementKey($complete_headers, $key_encryption_algorithm, $content_encryption_algorithm, $recipient_key, $sender_key);
        } elseif ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($recipient_key);
        } else {
            throw new \RuntimeException('Unable to get key management mode.');
        }
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\KeyEncryptionAlgorithmInterface
     */
    private function findKeyEncryptionAlgorithm(array $complete_headers)
    {
        if (!array_key_exists('alg', $complete_headers)) {
            throw new \InvalidArgumentException('Parameter "alg" is missing.');
        }
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        if ($key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
            return $key_encryption_algorithm;
        }
        throw new \RuntimeException(sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function findContentEncryptionAlgorithm(array $complete_headers)
    {
        if (!array_key_exists('enc', $complete_headers)) {
            throw new \InvalidArgumentException('Parameter "enc" is missing.');
        }

        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
            throw new \RuntimeException(sprintf('The algorithm "%s" is not enabled or does not implement ContentEncryptionInterface.', $complete_headers['enc']));
        }

        return $content_encryption_algorithm;
    }

    /**
     * @param array                                               $complete_headers
     * @param \Jose\Algorithm\KeyEncryption\KeyAgreementInterface $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param \Jose\Object\JWKInterface|null                      $sender_key
     *
     * @return string
     */
    private function calculateAgreementKey(array $complete_headers, KeyAgreementInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if (!$sender_key instanceof JWKInterface) {
            throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
        }
        $additional_header_values = [];
        $cek = $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $sender_key, $recipient_key, $complete_headers, $additional_header_values);

        return $cek;
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createCEK($size)
    {
        return $this->generateRandomString($size / 8);
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createIV($size)
    {
        return $this->generateRandomString($size / 8);
    }

    /**
     * @param int $length
     *
     * @return string
     */
    private function generateRandomString($length)
    {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        } else {
            return openssl_random_pseudo_bytes($length);
        }
    }
}
