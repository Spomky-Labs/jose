<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
use Jose\JSONSerializationModes;
use Jose\JWAInterface;
use Jose\JWEInterface;
use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use Jose\Operation\ContentEncryptionInterface;
use Jose\Operation\DirectEncryptionInterface;
use Jose\Operation\KeyAgreementInterface;
use Jose\Operation\KeyAgreementWrappingInterface;
use Jose\Operation\KeyEncryptionInterface;
use Jose\Operation\SignatureInterface;
use SpomkyLabs\Jose\Behaviour\HasCheckerManager;
use SpomkyLabs\Jose\Behaviour\HasCompressionManager;
use SpomkyLabs\Jose\Behaviour\HasJWAManager;
use SpomkyLabs\Jose\Behaviour\HasJWKManager;
use SpomkyLabs\Jose\Behaviour\HasJWKSetManager;
use SpomkyLabs\Jose\Behaviour\HasJWTManager;
use SpomkyLabs\Jose\Behaviour\HasKeyChecker;
use SpomkyLabs\Jose\Behaviour\HasPayloadConverter;
use SpomkyLabs\Jose\Util\Converter;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
class Loader implements LoaderInterface
{
    use HasKeyChecker;
    use HasJWAManager;
    use HasJWTManager;
    use HasJWKManager;
    use HasJWKSetManager;
    use HasCheckerManager;
    use HasPayloadConverter;
    use HasCompressionManager;

    /**
     * {@inheritdoc}
     */
    public function load($input)
    {
        $json = Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION, false);
        if (is_array($json)) {
            if (array_key_exists('signatures', $json)) {
                return $this->loadSerializedJsonJWS($json);
            }
            if (array_key_exists('recipients', $json)) {
                return $this->loadSerializedJsonJWE($json);
            }
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(JWEInterface &$jwe, JWKSetInterface $jwk_set = null)
    {
        $complete_header = array_merge(
            $jwe->getProtectedHeader(),
            $jwe->getUnprotectedHeader()
        );

        $this->checkCompleteHeader($complete_header);

        if (is_null($jwk_set)) {
            $jwk_set = $this->getKeysFromCompleteHeader($complete_header);
        }
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header['alg']);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_header['enc']);

        foreach ($jwk_set as $jwk) {
            if (!$this->checkKeyUsage($jwk, 'decryption')) {
                continue;
            }
            if (!$this->checkKeyAlgorithm($jwk, $key_encryption_algorithm->getAlgorithmName())) {
                continue;
            }
            $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $jwe->getEncryptedKey(), $complete_header);

            if (!is_null($cek)) {
                return $this->decryptPayload($jwe, $cek, $content_encryption_algorithm);
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function verifySignature(JWSInterface $jws, JWKSetInterface $jwk_set = null)
    {
        $complete_header = array_merge($jws->getProtectedHeader(), $jws->getUnprotectedHeader());
        if (is_null($jwk_set)) {
            $jwk_set = $this->getKeysFromCompleteHeader($complete_header);
        }

        if (0 === count($jwk_set)) {
            return false;
        }
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($complete_header, $jwk);
            if (!$this->checkKeyUsage($jwk, 'verification')) {
                continue;
            }
            if (!$this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName())) {
                continue;
            }
            if (true === $algorithm->verify($jwk, $jws->getInput(), $jws->getSignature())) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWTInterface $jwt)
    {
        $this->getCheckerManager()->checkJWT($jwt);

        return true;
    }

    /**
     * @param array $data
     *
     * @return \Jose\JWSInterface|\Jose\JWSInterface[]
     */
    protected function loadSerializedJsonJWS(array $data)
    {
        $encoded_payload = $data['payload'];
        $payload = Base64Url::decode($encoded_payload);

        $jws = [];
        foreach ($data['signatures'] as $signature) {
            if (array_key_exists('protected', $signature)) {
                $encoded_protected_header = $signature['protected'];
                $protected_header = json_decode(Base64Url::decode($encoded_protected_header), true);
            } else {
                $encoded_protected_header = null;
                $protected_header = [];
            }
            $unprotected_header = isset($signature['header']) ? $signature['header'] : [];

            $jws[] = $this->createJWS($encoded_protected_header.'.'.$encoded_payload, $protected_header, $unprotected_header, $payload, Base64Url::decode($signature['signature']));
        }

        return count($jws) > 1 ? $jws : current($jws);
    }

    /**
     * @param string $input
     * @param $protected_header
     * @param $unprotected_header
     * @param string $payload
     * @param string $signature
     *
     * @throws \Exception
     *
     * @return \Jose\JWSInterface
     */
    protected function createJWS($input, $protected_header, $unprotected_header, $payload, $signature)
    {
        $complete_header = array_merge($protected_header, $unprotected_header);
        $payload = $this->getPayloadConverter()->convertStringToPayload($complete_header, $payload);
        $jws = $this->getJWTManager()->createJWS();
        $jws->setPayload($payload);
        $jws->setInput($input);
        $jws->setSignature($signature);
        if (!empty($protected_header)) {
            $jws->setProtectedHeader($protected_header);
        }
        if (!empty($unprotected_header)) {
            $jws->setUnprotectedHeader($unprotected_header);
        }

        return $jws;
    }

    /**
     * @param $protected_header
     * @param $unprotected_header
     *
     * @return array
     */
    protected function getCompleteHeader($protected_header, $unprotected_header)
    {
        $complete_header = [];
        if (!is_null($protected_header)) {
            $tmp = json_decode(Base64Url::decode($protected_header), true);
            if (!is_array($tmp)) {
                throw new \InvalidArgumentException('Invalid protected header');
            }
            $complete_header = array_merge($complete_header, $tmp);
        }
        if (is_array($unprotected_header)) {
            $complete_header = array_merge($complete_header, $unprotected_header);
        }

        return $complete_header;
    }

    /**
     * @param array              $header
     * @param \Jose\JWKInterface $key
     *
     * @return \Jose\Operation\SignatureInterface|null
     */
    protected function getAlgorithm(array $header, JWKInterface $key)
    {
        if (!array_key_exists('alg', $header)) {
            if (is_null($key->getAlgorithm())) {
                throw new \InvalidArgumentException("No 'alg' parameter set in the header or the key.");
            } else {
                $alg = $key->getAlgorithm();
            }
        } else {
            $alg = $header['alg'];
        }

        $algorithm = $this->getJWAManager()->getAlgorithm($alg);
        if (!$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException("The algorithm '$alg' is not supported or does not implement SignatureInterface.");
        }

        return $algorithm;
    }

    /**
     * @param \Jose\JWAInterface                         $key_encryption_algorithm
     * @param \Jose\Operation\ContentEncryptionInterface $content_encryption_algorithm
     * @param \Jose\JWKInterface                         $key
     * @param string|null                                $encrypted_cek
     * @param array                                      $header
     *
     * @return string|null
     */
    public function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionInterface $content_encryption_algorithm, JWKInterface $key, $encrypted_cek, array $header)
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
     * @param array $data
     *
     * @return \Jose\JWEInterface|\Jose\JWEInterface[]
     */
    protected function loadSerializedJsonJWE(array $data)
    {
        $result = [];
        foreach ($data['recipients'] as $recipient) {
            $encoded_protected_header = array_key_exists('protected', $data) ? $data['protected'] : '';
            $protected_header = empty($encoded_protected_header) ? [] : json_decode(Base64Url::decode($encoded_protected_header), true);
            $unprotected_header = array_key_exists('unprotected', $data) ? $data['unprotected'] : [];
            $header = array_key_exists('header', $recipient) ? $recipient['header'] : [];

            $jwe = $this->getJWTManager()->createJWE();
            $jwe->setAAD(array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null)
                ->setCiphertext(Base64Url::decode($data['ciphertext']))
                ->setEncryptedKey(array_key_exists('encrypted_key', $recipient) ? Base64Url::decode($recipient['encrypted_key']) : null)
                ->setIV(array_key_exists('iv', $data) ? Base64Url::decode($data['iv']) : null)
                ->setTag(array_key_exists('tag', $data) ? Base64Url::decode($data['tag']) : null)
                ->setProtectedHeader($protected_header)
                ->setEncodedProtectedHeader($encoded_protected_header)
                ->setUnprotectedHeader(array_merge($unprotected_header, $header));
            $result[] = $jwe;
        }

        return count($result) > 1 ? $result : current($result);
    }

    /**
     * @param \Jose\JWEInterface                         $jwe
     * @param string                                     $cek
     * @param \Jose\Operation\ContentEncryptionInterface $content_encryption_algorithm
     *
     * @return \Jose\JWEInterface
     */
    protected function decryptPayload(JWEInterface &$jwe, $cek, $content_encryption_algorithm)
    {
        $payload = $content_encryption_algorithm->decryptContent(
            $jwe->getCiphertext(),
            $cek,
            $jwe->getIV(),
            $jwe->getAAD(),
            $jwe->getEncodedProtectedHeader(),
            $jwe->getTag()
        );

        if (is_null($payload)) {
            return false;
        }

        if (!is_null($jwe->getZip())) {
            $compression_method = $this->getCompressionMethod($jwe->getZip());
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                throw new \RuntimeException('Decompression failed');
            }
        }

        $payload = $this->getPayloadConverter()->convertStringToPayload(array_merge($jwe->getProtectedHeader(), $jwe->getUnprotectedHeader()), $payload);

        $jwe->setPayload($payload);

        return true;
    }

    /**
     * @param array $complete_header
     *
     * @throws \InvalidArgumentException
     */
    protected function checkCompleteHeader(array $complete_header)
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
     * @return \Jose\Operation\DirectEncryptionInterface|\Jose\Operation\KeyEncryptionInterface|\Jose\Operation\KeyAgreementInterface|\Jose\Operation\KeyAgreementWrappingInterface
     */
    protected function getKeyEncryptionAlgorithm($algorithm)
    {
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        foreach ([
                    '\Jose\Operation\DirectEncryptionInterface',
                    '\Jose\Operation\KeyEncryptionInterface',
                    '\Jose\Operation\KeyAgreementInterface',
                    '\Jose\Operation\KeyAgreementWrappingInterface',
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
     * @return \Jose\Operation\ContentEncryptionInterface
     */
    protected function getContentEncryptionAlgorithm($algorithm)
    {
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
            throw new \RuntimeException("The algorithm '".$algorithm."' does not implement ContentEncryptionInterface.");
        }

        return $content_encryption_algorithm;
    }

    protected function getCompressionMethod($method)
    {
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        if (is_null($compression_method)) {
            throw new \RuntimeException(sprintf("Compression method '%s' not supported"), $method);
        }

        return $compression_method;
    }

    protected function getKeysFromCompleteHeader(array $header)
    {
        $keys = $this->getJWKSetManager()->createJWKSet();
        $jwk = $this->getJWKManager()->findByHeader($header);
        if ($jwk instanceof JWKInterface) {
            $keys->addKey($jwk);
        }
        $jwkset = $this->getJWKSetManager()->findByHeader($header);
        if ($jwkset instanceof JWKSetInterface) {
            foreach ($jwkset as $key) {
                $keys->addKey($key);
            }
        } elseif ($jwkset instanceof JWKInterface) {
            $keys->addKey($jwkset);
        }

        return $keys;
    }
}
