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

use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\JWAManagerInterface;
use Jose\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Behaviour\HasCheckerManager;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Checker\CheckerManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\RecipientInterface;

/**
 */
final class Decrypter implements DecrypterInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCheckerManager;
    use HasCompressionManager;

    /**
     * Loader constructor.
     *
     * @param \Jose\Algorithm\JWAManagerInterface           $jwa_manager
     * @param \Jose\Compression\CompressionManagerInterface $compression_manager
     * @param \Jose\Checker\CheckerManagerInterface         $checker_manager
     */
    public function __construct(
        JWAManagerInterface $jwa_manager,
        CompressionManagerInterface $compression_manager,
        CheckerManagerInterface $checker_manager)
    {
        $this->setJWAManager($jwa_manager);
        $this->setCompressionManager($compression_manager);
        $this->setCheckerManager($checker_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptUsingKey(JWEInterface &$jwe, JWKInterface $jwk)
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey($jwk);

        return $this->decryptUsingKeySet($jwe, $jwk_set);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptUsingKeySet(JWEInterface &$jwe, JWKSetInterface $jwk_set)
    {
        foreach ($jwe->getRecipients() as $recipient) {
            $complete_headers = array_merge(
                $jwe->getSharedProtectedHeaders(),
                $jwe->getSharedHeaders(),
                $recipient->getHeaders()
            );
            $this->checkCompleteHeader($complete_headers);

            $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_headers);
            $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_headers);

            foreach ($jwk_set as $jwk) {
                try {
                    $this->checkKeyUsage($jwk, 'decryption');
                    $this->checkKeyAlgorithm($jwk, $key_encryption_algorithm->getAlgorithmName());
                    $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $complete_headers);
                    if (null !== $cek) {
                        if (true === $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $complete_headers)) {
                            $this->getCheckerManager()->checkJWT($jwe);
                            
                            return true;
                        };
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
     * @param \Jose\Algorithm\JWAInterface                        $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $key
     * @param \Jose\Object\RecipientInterface                     $recipient
     * @param array                                               $complete_headers
     *
     * @return null|string
     */
    private function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $key, RecipientInterface $recipient, array $complete_headers)
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey(
                $content_encryption_algorithm->getCEKSize(),
                $key,
                null,
                $complete_headers
            );
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey(
                $key,
                $recipient->getEncryptedKey(),
                $content_encryption_algorithm->getCEKSize(),
                $complete_headers
            );
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey(
                $key,
                $recipient->getEncryptedKey(),
                $complete_headers
            );
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $key_encryption_algorithm->unwrapKey(
                $key,
                $recipient->getEncryptedKey(),
                $complete_headers
            );
        } else {
            throw new \InvalidArgumentException('Unsupported CEK generation');
        }
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param string                                              $cek
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $complete_headers
     *
     * @return bool
     */
    private function decryptPayload(JWEInterface &$jwe, $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array $complete_headers)
    {
        $payload = $content_encryption_algorithm->decryptContent(
            $jwe->getCiphertext(),
            $cek,
            $jwe->getIV(),
            $jwe->getAAD(),
            $jwe->getEncodedSharedProtectedHeaders(),
            $jwe->getTag()
        );

        if (null === $payload) {
            return false;
        }

        if (array_key_exists('zip', $complete_headers)) {
            $compression_method = $this->getCompressionMethod($complete_headers['zip']);
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                throw new \InvalidArgumentException('Decompression failed');
            }
        }

        $jwe = $jwe->withContentEncryptionKey($cek);

        $decoded = json_decode($payload, true);
        $jwe = $jwe->withPayload(null === $decoded ? $payload : $decoded);

        return true;
    }

    /**
     * @param array $complete_headers
     *
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $complete_headers)
    {
        foreach (['enc', 'alg'] as $key) {
            if (!array_key_exists($key, $complete_headers)) {
                throw new \InvalidArgumentException(sprintf("Parameters '%s' is missing.", $key));
            }
        }
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\KeyEncryptionAlgorithmInterface
     */
    private function getKeyEncryptionAlgorithm(array $complete_headers)
    {
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);

        if (!$key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf("The key encryption algorithm '%s' is not supported or does not implement KeyEncryptionAlgorithmInterface.", $complete_headers['alg']));
        }

        return $key_encryption_algorithm;
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(array $complete_headers)
    {
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" does not exist or does not implement ContentEncryptionInterface."', $complete_headers['enc']));
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
}
