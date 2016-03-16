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
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasLogger;
use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManagerInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\RecipientInterface;
use Jose\Util\StringUtil;
use Psr\Log\LoggerInterface;

final class Encrypter implements EncrypterInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCompressionManager;
    use HasLogger;

    /**
     * Encrypter constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface           $jwa_manager
     * @param \Jose\Compression\CompressionManagerInterface $compression_manager
     * @param \Psr\Log\LoggerInterface|null                 $logger
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        CompressionManagerInterface $compression_manager,
        LoggerInterface $logger = null
    ) {
        $this->setJWAManager($jwa_manager);
        $this->setCompressionManager($compression_manager);

        if (null !== $logger) {
            $this->setLogger($logger);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(JWEInterface &$jwe)
    {
        Assertion::greaterThan($jwe->countRecipients(), 0, 'The JWE does not contain recipient.');

        // Content Encryption Algorithm
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($jwe);

        // Compression Method
        $compression_method = $this->getCompressionMethod($jwe);

        // Key Management Mode
        $key_management_mode = $this->getKeyManagementMode($jwe);

        // Additional Headers
        $additional_headers = [];

        // CEK
        $cek = $this->determineCEK(
            $jwe,
            $content_encryption_algorithm,
            $key_management_mode,
            $additional_headers
        );

        for ($i = 0; $i < $jwe->countRecipients(); $i++) {
            $this->processRecipient(
                $jwe,
                $jwe->getRecipient($i),
                $cek,
                $content_encryption_algorithm,
                $additional_headers
            );
        }

        if (!empty($additional_headers) && 1 === $jwe->countRecipients()) {
            $jwe = $jwe->withSharedProtectedHeaders(array_merge(
                $jwe->getSharedProtectedHeaders(),
                $additional_headers
            ));
        }

        // IV
        if (null !== $iv_size = $content_encryption_algorithm->getIVSize()) {
            $iv = $this->createIV($iv_size);
            $jwe = $jwe->withIV($iv);
        }

        $jwe = $jwe->withContentEncryptionKey($cek);

        $this->encryptJWE($jwe, $content_encryption_algorithm, $compression_method);
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param \Jose\Object\RecipientInterface                     $recipient
     * @param string                                              $cek
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $additional_headers
     */
    private function processRecipient(JWEInterface $jwe,
                                      RecipientInterface &$recipient,
                                      $cek,
                                      ContentEncryptionAlgorithmInterface $content_encryption_algorithm,
                                      array &$additional_headers
    ) {
        $complete_headers = array_merge(
            $jwe->getSharedProtectedHeaders(),
            $jwe->getSharedHeaders(),
            $recipient->getHeaders()
        );

        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

        // We check keys (usage and algorithm if restrictions are set)
        $this->checkKeys(
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $recipient->getRecipientKey()
        );

        $encrypted_content_encryption_key = $this->getEncryptedKey(
            $complete_headers,
            $cek,
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $additional_headers,
            $recipient->getRecipientKey()
        );

        if (!empty($additional_headers) && 1 !== $jwe->countRecipients()) {
            foreach ($additional_headers as $key => $value) {
                $recipient = $recipient->withHeader($key, $value);
            }
        }
        if (null !== $encrypted_content_encryption_key) {
            $recipient = $recipient->withEncryptedKey($encrypted_content_encryption_key);
        }
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param string                                              $key_management_mode
     * @param array                                               $additional_headers
     *
     * @return string
     */
    private function determineCEK(JWEInterface $jwe,
                                  ContentEncryptionAlgorithmInterface $content_encryption_algorithm,
                                  $key_management_mode,
                                  array &$additional_headers
    ) {
        switch ($key_management_mode) {
            case KeyEncryptionInterface::MODE_ENCRYPT:
            case KeyEncryptionInterface::MODE_WRAP:
                return $this->createCEK($content_encryption_algorithm->getCEKSize());
            case KeyEncryptionInterface::MODE_AGREEMENT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');

                $complete_headers = array_merge(
                    $jwe->getSharedProtectedHeaders(),
                    $jwe->getSharedHeaders(),
                    $jwe->getRecipient(0)->getHeaders()
                );
                $algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

                return $algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->getAlgorithmName(), $jwe->getRecipient(0)->getRecipientKey(), $complete_headers, $additional_headers);
            case KeyEncryptionInterface::MODE_DIRECT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');

                Assertion::eq($jwe->getRecipient(0)->getRecipientKey()->get('kty'), 'oct', 'Wrong key type.');
                Assertion::true($jwe->getRecipient(0)->getRecipientKey()->has('k'), 'The key parameter "k" is missing.');

                return Base64Url::decode($jwe->getRecipient(0)->getRecipientKey()->get('k'));
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key management mode "%s".', $key_management_mode));
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return string
     */
    private function getKeyManagementMode(JWEInterface $jwe)
    {
        $mode = null;

        foreach ($jwe->getRecipients() as $recipient) {
            $complete_headers = array_merge(
                $jwe->getSharedProtectedHeaders(),
                $jwe->getSharedHeaders(),
                $recipient->getHeaders()
            );
            Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');

            $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
            Assertion::isInstanceOf($key_encryption_algorithm, KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

            if (null === $mode) {
                $mode = $key_encryption_algorithm->getKeyManagementMode();
            } else {
                Assertion::true(
                    $this->areKeyManagementModesCompatible($mode, $key_encryption_algorithm->getKeyManagementMode()),
                    'Foreign key management mode forbidden.'
                );
            }
        }

        return $mode;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function getCompressionMethod(JWEInterface $jwe)
    {
        $method = null;

        for ($i = 0; $i < $jwe->countRecipients(); $i++) {
            $complete_headers = array_merge(
                $jwe->getSharedProtectedHeaders(),
                $jwe->getSharedHeaders(),
                $jwe->getRecipient($i)->getHeaders()
            );
            if (array_key_exists('zip', $complete_headers)) {
                if (null === $method) {
                    if (0 === $i) {
                        $method = $complete_headers['zip'];
                    } else {
                        throw new \InvalidArgumentException('Inconsistent "zip" parameter.');
                    }
                } else {
                    Assertion::eq($method, $complete_headers['zip'], 'Inconsistent "zip" parameter.');
                }
            } else {
                Assertion::eq(null, $method, 'Inconsistent "zip" parameter.');
            }
        }

        if (null === $method) {
            return;
        }

        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        Assertion::isInstanceOf($compression_method, CompressionInterface::class, sprintf('Compression method "%s" not supported.', $method));

        return $compression_method;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(JWEInterface $jwe)
    {
        $algorithm = null;

        foreach ($jwe->getRecipients() as $recipient) {
            $complete_headers = array_merge(
                $jwe->getSharedProtectedHeaders(),
                $jwe->getSharedHeaders(),
                $recipient->getHeaders()
            );
            Assertion::keyExists($complete_headers, 'enc', 'Parameter "enc" is missing.');
            if (null === $algorithm) {
                $algorithm = $complete_headers['enc'];
            } else {
                Assertion::eq($algorithm, $complete_headers['enc'], 'Foreign content encryption algorithms are not allowed.');
            }
        }

        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        Assertion::isInstanceOf($content_encryption_algorithm, ContentEncryptionAlgorithmInterface::class, sprintf('The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.', $algorithm));

        return $content_encryption_algorithm;
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Compression\CompressionInterface|null         $compression_method
     */
    private function encryptJWE(JWEInterface &$jwe,
                                ContentEncryptionAlgorithmInterface $content_encryption_algorithm,
                                CompressionInterface $compression_method = null
    ) {
        if (!empty($jwe->getSharedProtectedHeaders())) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders(Base64Url::encode(json_encode($jwe->getSharedProtectedHeaders())));
        }

        // We encrypt the payload and get the tag
        $tag = null;
        $payload = $this->preparePayload($jwe->getPayload(), $compression_method);

        $ciphertext = $content_encryption_algorithm->encryptContent(
            $payload,
            $jwe->getContentEncryptionKey(),
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
    }

    /**
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     */
    private function checkKeys(KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $recipient_key)
    {
        $this->checkKeyUsage($recipient_key, 'encryption');
        if ('dir' !== $key_encryption_algorithm->getAlgorithmName()) {
            $this->checkKeyAlgorithm($recipient_key, $key_encryption_algorithm->getAlgorithmName());
        } else {
            $this->checkKeyAlgorithm($recipient_key, $content_encryption_algorithm->getAlgorithmName());
        }
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
            $enc.$enc     => true,
            $enc.$wrap    => true,
            $wrap.$enc    => true,
            $wrap.$wrap   => true,
            $agree.$agree => false,
            $agree.$dir   => false,
            $agree.$enc   => false,
            $agree.$wrap  => false,
            $dir.$agree   => false,
            $dir.$dir     => false,
            $dir.$enc     => false,
            $dir.$wrap    => false,
            $enc.$agree   => false,
            $enc.$dir     => false,
            $wrap.$agree  => false,
            $wrap.$dir    => false,
        ];

        if (array_key_exists($current.$new, $supported_key_management_mode_combinations)) {
            return $supported_key_management_mode_combinations[$current.$new];
        }

        return false;
    }

    /**
     * @param string                                      $payload
     * @param \Jose\Compression\CompressionInterface|null $compression_method
     *
     * @return string
     */
    private function preparePayload($payload, CompressionInterface $compression_method = null)
    {
        $prepared = is_string($payload) ? $payload : json_encode($payload);

        Assertion::notNull($prepared, 'The payload is empty or cannot encoded into JSON.');

        if (null === $compression_method) {
            return $prepared;
        }
        $compressed_payload = $compression_method->compress($prepared);
        Assertion::string($compressed_payload, 'Compression failed.');

        return $compressed_payload;
    }

    /**
     * @param array                                               $complete_headers
     * @param string                                              $cek
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     * @param array                                               $additional_headers
     *
     * @return string|null
     */
    private function getEncryptedKey(array $complete_headers, $cek, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key)
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient_key);
        }

        // Using KeyAgreementInterface or DirectEncryptionInterface, the encrypted key is an empty string
    }

    /**
     * @param array                                                       $complete_headers
     * @param string                                                      $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface         $content_encryption_algorithm
     * @param array                                                       $additional_headers
     * @param \Jose\Object\JWKInterface                                   $recipient_key
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(array $complete_headers, $cek, KeyAgreementWrappingInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key)
    {
        $jwt_cek = $key_encryption_algorithm->wrapAgreementKey($recipient_key, $cek, $content_encryption_algorithm->getCEKSize(), $complete_headers, $additional_headers);

        return $jwt_cek;
    }

    /**
     * @param array                                                $complete_headers
     * @param string                                               $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyEncryptionInterface $key_encryption_algorithm
     * @param \Jose\Object\JWKInterface                            $recipient_key
     * @param array                                                $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyEncryptionAlgorithm(array $complete_headers, $cek, KeyEncryptionInterface $key_encryption_algorithm, JWKInterface $recipient_key, array &$additional_headers)
    {
        return $key_encryption_algorithm->encryptKey(
            $recipient_key,
            $cek,
            $complete_headers,
            $additional_headers
        );
    }

    /**
     * @param array                                              $complete_headers
     * @param string                                             $cek
     * @param \Jose\Algorithm\KeyEncryption\KeyWrappingInterface $key_encryption_algorithm
     * @param \Jose\Object\JWKInterface                          $recipient_key
     * @param array                                              $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyWrappingAlgorithm(array $complete_headers, $cek, KeyWrappingInterface $key_encryption_algorithm, JWKInterface $recipient_key, &$additional_headers)
    {
        return $key_encryption_algorithm->wrapKey(
            $recipient_key,
            $cek,
            $complete_headers,
            $additional_headers
        );
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\KeyEncryptionAlgorithmInterface
     */
    private function findKeyEncryptionAlgorithm(array $complete_headers)
    {
        Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');

        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($key_encryption_algorithm, KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

        return $key_encryption_algorithm;
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createCEK($size)
    {
        return StringUtil::generateRandomBytes($size / 8);
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createIV($size)
    {
        return StringUtil::generateRandomBytes($size / 8);
    }
}
