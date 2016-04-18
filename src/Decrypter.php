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
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Behaviour\CommonCipheringMethods;
use Jose\Behaviour\HasCompressionManager;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasLogger;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Factory\CompressionManagerFactory;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\RecipientInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class Decrypter implements DecrypterInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasCompressionManager;
    use HasLogger;
    use CommonCipheringMethods;

    /**
     * {@inheritdoc}
     */
    public static function createDecrypter(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF', 'ZLIB', 'GZ'], LoggerInterface $logger = null)
    {
        $decrypter = new self($key_encryption_algorithms, $content_encryption_algorithms, $compression_methods);
        
        if (null !== $logger) {
            $decrypter->enableLogging($logger);
        }
        
        return $decrypter;
    }

    /**
     * Decrypter constructor.
     *
     * @param string[]|\Jose\Algorithm\KeyEncryptionAlgorithmInterface[]     $key_encryption_algorithms
     * @param string[]|\Jose\Algorithm\ContentEncryptionAlgorithmInterface[] $content_encryption_algorithms
     * @param string[]|\Jose\Compression\CompressionInterface[]              $compression_methods
     */
    public function __construct(
        array $key_encryption_algorithms,
        array $content_encryption_algorithms,
        array $compression_methods
    ) {
        $this->setKeyEncryptionAlgorithms($key_encryption_algorithms);
        $this->setContentEncryptionAlgorithms($content_encryption_algorithms);
        $this->setCompressionMethods($compression_methods);
        $this->setJWAManager(AlgorithmManagerFactory::createAlgorithmManager(array_merge(
            $key_encryption_algorithms,
            $content_encryption_algorithms
        )));
        $this->setCompressionManager(CompressionManagerFactory::createCompressionManager($compression_methods));
    }

    /**
     * {@inheritdoc}
     */
    public function decryptUsingKey(JWEInterface &$jwe, JWKInterface $jwk, &$recipient_index = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->decryptUsingKeySet($jwe, $jwk_set, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptUsingKeySet(JWEInterface &$jwe, JWKSetInterface $jwk_set, &$recipient_index = null)
    {
        $this->log(LogLevel::DEBUG, 'Trying to decrypt the JWE.');
        $this->checkJWKSet($jwk_set);
        $this->checkPayload($jwe);
        $this->checkRecipients($jwe);

        $nb_recipients = $jwe->countRecipients();
        $this->log(LogLevel::DEBUG, 'The JWE contains {nb} recipient(s).', ['nb' => $nb_recipients]);

        for ($i = 0; $i < $nb_recipients; $i++) {
            if (is_int($result = $this->decryptRecipientKey($jwe, $jwk_set, $i))) {
                $recipient_index = $result;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to decrypt the JWE.');
    }

    /**
     * @param \Jose\Object\JWEInterface    $jwe
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param int                          $i
     *
     * @return mixed
     */
    private function decryptRecipientKey(JWEInterface &$jwe, JWKSetInterface $jwk_set, $i)
    {
        $this->log(LogLevel::DEBUG, 'Trying to decrypt the encrypted key of recipient #{nb}.', ['nb' => $i]);
        $recipient = $jwe->getRecipient($i);
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
                if ('dir' !== $key_encryption_algorithm->getAlgorithmName()) {
                    $this->checkKeyAlgorithm($jwk, $key_encryption_algorithm->getAlgorithmName());
                } else {
                    $this->checkKeyAlgorithm($jwk, $content_encryption_algorithm->getAlgorithmName());
                }
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $complete_headers);
                if (null !== $cek) {
                    if (true === $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $complete_headers)) {
                        return $i;
                    };
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     */
    private function checkRecipients(JWEInterface $jwe)
    {
        if (0 === $jwe->countRecipients()) {
            $exception = new \InvalidArgumentException('The JWE does not contain any recipient.');
            $this->log(LogLevel::ERROR, 'The JWE does not contain any recipient.', ['exception' => $exception]);
            throw $exception;
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     */
    private function checkPayload(JWEInterface $jwe)
    {
        $this->log(LogLevel::DEBUG, 'Checking the payload.', ['payload' => $jwe->getPayload()]);
        if (null !== $jwe->getPayload()) {
            $exception = new \InvalidArgumentException('The JWE is already decrypted.');
            $this->log(LogLevel::ERROR, 'The JWE is already decrypted.', ['exception' => $exception]);
            throw $exception;
        }
    }

    /**
     * @param \Jose\Object\JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        $this->log(LogLevel::DEBUG, 'Checking the key set.', ['jwkset' => $jwk_set]);
        if (0 === count($jwk_set)) {
            $exception = new \InvalidArgumentException('No key in the key set.');
            $this->log(LogLevel::ERROR, 'There is no key in the key set.', ['exception' => $exception]);
            throw $exception;
        }
        $this->log(LogLevel::DEBUG, 'Checking the key set.', ['jwkset' => $jwk_set]);
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
                $content_encryption_algorithm->getAlgorithmName(),
                $key,
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
            null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD()),
            $jwe->getEncodedSharedProtectedHeaders(),
            $jwe->getTag()
        );
        if (null === $payload) {
            return false;
        }

        $this->decompressIfNeeded($payload, $complete_headers);

        $decoded = json_decode($payload, true);
        $jwe = $jwe->withPayload(null === $decoded ? $payload : $decoded);

        return true;
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     */
    private function decompressIfNeeded(&$payload, array $complete_headers)
    {
        $this->log(LogLevel::DEBUG, 'Checking if payload is compressed.', ['payload' => $payload]);
        if (array_key_exists('zip', $complete_headers)) {
            $this->log(LogLevel::DEBUG, 'Header indicates the payload is compressed with method {compress}.', ['compress' => $complete_headers['zip']]);
            $compression_method = $this->getCompressionMethod($complete_headers['zip']);
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                $exception = new \InvalidArgumentException('Decompression failed');
                $this->log(LogLevel::ERROR, 'Unable to decompress the payload.', ['exception' => $exception]);
                throw $exception;
            }
            $this->log(LogLevel::DEBUG, 'The payload has been decompressed.');
        } else {
            $this->log(LogLevel::DEBUG, 'The payload is not compressed.');
        }
    }

    /**
     * @param array $complete_headers
     *
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $complete_headers)
    {
        $this->log(LogLevel::DEBUG, 'Checking for mandatory parameters.');
        foreach (['enc', 'alg'] as $key) {
            if (!array_key_exists($key, $complete_headers)) {
                $exception = new \InvalidArgumentException(sprintf("Parameters '%s' is missing.", $key));
                $this->log(LogLevel::ERROR, 'Parameter is missing.', ['exception' => $exception]);
                throw $exception;
            }
        }
        $this->log(LogLevel::DEBUG, 'Mandatory parameters found.');
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\KeyEncryptionAlgorithmInterface
     */
    private function getKeyEncryptionAlgorithm(array $complete_headers)
    {
        $this->log(LogLevel::DEBUG, 'Trying to find key encryption algorithm');
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        if (!$key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
            $exception = new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or does not implement KeyEncryptionAlgorithmInterface.', $complete_headers['alg']));
            $this->log(LogLevel::ERROR, 'The key encryption algorithm {alg} is not supported or does not implement KeyEncryptionAlgorithmInterface.', ['alg' => $complete_headers['alg'], 'exception' => $exception]);
            throw $exception;
        }

        $this->log(LogLevel::DEBUG, 'Key encryption algorithm {algorithm} found', ['algorithm' => $complete_headers['alg'], 'service' > $key_encryption_algorithm]);

        return $key_encryption_algorithm;
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(array $complete_headers)
    {
        $this->log(LogLevel::DEBUG, 'Trying to find content encryption algorithm');
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
            $exception = new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or does not implement ContentEncryptionInterface.', $complete_headers['enc']));
            $this->log(LogLevel::ERROR, 'The key encryption algorithm {alg} is not supported or does not implement ContentEncryptionInterface.', ['alg' => $complete_headers['enc'], 'exception' => $exception]);
            throw $exception;
        }

        $this->log(LogLevel::DEBUG, 'Content encryption algorithm {algorithm} found', ['algorithm' => $complete_headers['enc'], 'service' > $content_encryption_algorithm]);

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
        $this->log(LogLevel::DEBUG, 'Trying to find compression method {method}', ['method' => $method]);
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        if (null === $compression_method) {
            $exception = new \InvalidArgumentException(sprintf('Compression method "%s" not supported', $method));
            $this->log(LogLevel::ERROR, 'Compression method {method} not supported', ['method' => $method, 'exception' => $exception]);
            throw $exception;
        }

        $this->log(LogLevel::DEBUG, 'Compression method {method} found', ['method' => $method, 'service' => $compression_method]);

        return $compression_method;
    }
}
