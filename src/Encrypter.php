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

        // Key Encryption Algorithm
        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

        // Content Encryption Algorithm
        $content_encryption_algorithm = $this->findContentEncryptionAlgorithm($complete_headers);

        // We check keys (usage and algorithm if restrictions are set)
        $this->checkKeys($key_encryption_algorithm, $recipient_key, $sender_key);

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
            $payload = $this->preparePayload($jwe->getPayload(), $complete_headers);

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

            $recipient = $this->computeRecipient(
                $jwe,
                $key_encryption_algorithm,
                $content_encryption_algorithm,
                $complete_headers,
                $recipient_headers,
                $recipient_key,
                $sender_key
            );

            $jwe = $jwe->addRecipient($recipient);
        } else {
            if (0 === $jwe->countRecipients()) {
                throw new \InvalidArgumentException('Invalid JWE. The payload is encrypted but no recipient is available.');
            }
            if (null === $jwe->getContentEncryptionKey()) {
                throw new \InvalidArgumentException('Unable to add a recipient. The JWE must be decrypted first.');
            }
            $current_key_management_mode = $this->getCurrentKeyManagementMode($jwe);

            if (false === $this->areKeyManagementModesCompatible($current_key_management_mode, $key_encryption_algorithm->getKeyManagementMode())) {
                throw new \InvalidArgumentException('Foreign key management mode forbidden.');
            }

            $recipient = $this->computeRecipient(
                $jwe,
                $key_encryption_algorithm,
                $content_encryption_algorithm,
                $complete_headers,
                $recipient_headers,
                $recipient_key,
                $sender_key
            );

            $jwe = $jwe->addRecipient($recipient);
        }

        return $jwe;
    }

    /**
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface $algorithm
     * @param \Jose\Object\JWKInterface                       $recipient_key
     * @param \Jose\Object\JWKInterface|null                  $sender_key
     */
    private function checkKeys(KeyEncryptionAlgorithmInterface $algorithm, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        $this->checkKeyUsage($recipient_key, 'encryption');
        $this->checkKeyAlgorithm($recipient_key, $algorithm->getAlgorithmName());
        if ($sender_key instanceof JWKInterface) {
            $this->checkKeyUsage($sender_key, 'encryption');
            $this->checkKeyAlgorithm($sender_key, $algorithm->getAlgorithmName());
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return string
     */
    private function getCurrentKeyManagementMode(JWEInterface $jwe)
    {
        $complete_headers = array_merge(
            $jwe->getSharedProtectedHeaders(),
            $jwe->getSharedHeaders(),
            $jwe->getRecipient(0)->getHeaders()
        );
        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

        return $key_encryption_algorithm->getKeyManagementMode();
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $complete_headers
     * @param array                                               $recipient_headers
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param \Jose\Object\JWKInterface|null                      $sender_key
     *
     * @return \Jose\Object\RecipientInterface
     */
    private function computeRecipient(JWEInterface $jwe, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array $complete_headers, array $recipient_headers, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        $recipient = new Recipient();
        $recipient = $recipient->withHeaders($recipient_headers);

        $additional_headers = [];
        $encrypted_content_encryption_key = $this->getEncryptedKey(
            $complete_headers,
            $jwe->getContentEncryptionKey(),
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $additional_headers,
            $recipient_key,
            $sender_key
        );
        if (!empty($additional_headers)) {
            foreach ($additional_headers as $key => $value) {
                $recipient = $recipient->withHeader($key, $value);
            }
        }
        if (null !== $encrypted_content_encryption_key) {
            $recipient = $recipient->withEncryptedKey($encrypted_content_encryption_key);
        }

        return $recipient;
    }

    /**
     * @param string $current
     * @param string $new
     *
     * @return bool
     */
    private function areKeyManagementModesCompatible($current, $new)
    {
        $agree = KeyEncryptionAlgorithmInterface::MODE_AGREEMENT;
        $dir = KeyEncryptionAlgorithmInterface::MODE_DIRECT;
        $enc = KeyEncryptionAlgorithmInterface::MODE_ENCRYPT;
        $wrap = KeyEncryptionAlgorithmInterface::MODE_WRAP;

        $supported_key_management_mode_combinations = [
            $agree.$enc => true,
            $agree.$wrap => true,
            $dir.$enc => true,
            $dir.$wrap => true,
            $enc.$enc => true,
            $enc.$wrap => true,
            $wrap.$enc => true,
            $wrap.$wrap => true,
            $agree.$agree => false,
            $agree.$dir => false,
            $dir.$agree => false,
            $dir.$dir => false,
            $enc.$agree => false,
            $enc.$dir => false,
            $wrap.$agree => false,
            $wrap.$dir => false,
        ];

        if (array_key_exists($current.$new, $supported_key_management_mode_combinations)) {
            return $supported_key_management_mode_combinations[$current.$new];
        }

        return false;
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     *
     * @return string
     */
    private function preparePayload($payload, array $complete_headers)
    {
        $prepared = is_string($payload) ? $payload : json_encode($payload);

        if (null === $prepared) {
            throw new \InvalidArgumentException('The payload is empty or cannot encoded into JSON.');
        }
        if (!array_key_exists('zip', $complete_headers)) {
            return $prepared;
        }

        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($complete_headers['zip']);
        if (null === $compression_method) {
            throw new \RuntimeException(sprintf('Compression method "%s" not supported', $complete_headers['zip']));
        }
        $compressed_payload = $compression_method->compress($prepared);
        if (!is_string($compressed_payload)) {
            throw new \RuntimeException('Compression failed.');
        }

        return $compressed_payload;
    }

    /**
     * @param array                                               $complete_headers
     * @param string                                              $cek
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param \Jose\Object\JWKInterface|null                      $sender_key
     * @param array                                               $additional_headers
     *
     * @return string|null
     */
    private function getEncryptedKey(array $complete_headers, $cek, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {

            return $this->getEncryptedKeyFroKeyEncryptionAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {

            return $this->getEncryptedKeyFroKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {

            return $this->getEncryptedKeyFroKeyAgreementAndKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient_key, $sender_key);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {

            return $this->getEncryptedKeyFroKeyAgreementAlgorithm($complete_headers, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient_key, $sender_key);
        }
    }

    /**
     * @param array                                               $complete_headers
     * @param \Jose\Algorithm\KeyEncryption\KeyAgreementInterface $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $additional_headers
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param \Jose\Object\JWKInterface|null                      $sender_key
     *
     * @return mixed
     */
    private function getEncryptedKeyFroKeyAgreementAlgorithm(array $complete_headers, KeyAgreementInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if (!$sender_key instanceof JWKInterface) {
            throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
        }
        $jwt_cek = $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $sender_key, $recipient_key, $complete_headers, $additional_headers);

        return $jwt_cek;
    }

    /**
     * @param array                                                       $complete_headers
     * @param string                                                      $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface         $content_encryption_algorithm
     * @param array                                                       $additional_headers
     * @param \Jose\Object\JWKInterface                                   $recipient_key
     * @param \Jose\Object\JWKInterface|null                              $sender_key
     *
     * @return string
     */
    private function getEncryptedKeyFroKeyAgreementAndKeyWrappingAlgorithm(array $complete_headers, $cek, KeyAgreementWrappingInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key, JWKInterface $sender_key = null)
    {
        if (!$sender_key instanceof JWKInterface) {
            throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
        }
        $jwt_cek = $key_encryption_algorithm->wrapAgreementKey($sender_key, $recipient_key, $cek, $content_encryption_algorithm->getCEKSize(), $complete_headers, $additional_headers);

        return $jwt_cek;
    }

    /**
     * @param array                                                $complete_headers
     * @param string                                               $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyEncryptionInterface $key_encryption_algorithm
     * @param \Jose\Object\JWKInterface                            $recipient_key
     *
     * @return string
     */
    private function getEncryptedKeyFroKeyEncryptionAlgorithm(array $complete_headers, $cek, KeyEncryptionInterface $key_encryption_algorithm, JWKInterface $recipient_key)
    {
        return $key_encryption_algorithm->encryptKey(
            $recipient_key,
            $cek,
            $complete_headers
        );
    }

    /**
     * @param array                                              $complete_headers
     * @param string                                             $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyWrappingInterface $key_encryption_algorithm
     * @param \Jose\Object\JWKInterface                          $recipient_key
     *
     * @return string
     */
    private function getEncryptedKeyFroKeyWrappingAlgorithm(array $complete_headers, $cek, KeyWrappingInterface $key_encryption_algorithm, JWKInterface $recipient_key)
    {
        return $key_encryption_algorithm->wrapKey(
            $recipient_key,
            $cek,
            $complete_headers
        );
    }

    /**
     * @param array                                               $complete_headers
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param \Jose\Object\JWKInterface|null                      $sender_key
     *
     * @return string
     */
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
        throw new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));
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
