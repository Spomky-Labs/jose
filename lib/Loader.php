<?php

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
use Jose\JSONSerializationModes;
use Jose\JWAInterface;
use Jose\JWSInterface;
use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;
use Jose\LoaderInterface;
use Jose\Operation\SignatureInterface;
use Jose\Operation\KeyAgreementInterface;
use Jose\Operation\KeyAgreementWrappingInterface;
use Jose\Operation\KeyEncryptionInterface;
use Jose\Operation\DirectEncryptionInterface;
use Jose\Operation\ContentEncryptionInterface;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
abstract class Loader implements LoaderInterface
{
    use PayloadConverter;

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    /**
     * @return \Jose\Compression\CompressionManagerInterface
     */
    abstract protected function getCompressionManager();

    /**
     * {@inheritdoc}
     */
    public function load($input, JWKSetInterface $jwk_set = null)
    {
        $json = Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION, false);
        if (!is_null($json)) {
            if (array_key_exists('signatures', $json)) {
                return $this->loadSerializedJsonJWS($json);
            }
            if (array_key_exists('recipients', $json)) {
                return $this->loadSerializedJsonJWE($json, $jwk_set);
            }
        }
        throw new \InvalidArgumentException('Unable to load the input');
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
        $algorithm = $this->getAlgorithm($complete_header);
        foreach ($jwk_set->getKeys() as $jwk) {
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
        $methods = array('checkExpirationTime', 'checkNotBefore', 'checkIssuedAt', 'checkCritical');
        foreach ($methods as $method) {
            $this->$method($jwt);
        }

        return true;
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception
     */
    protected function checkExpirationTime(JWTInterface $jwt)
    {
        if (!is_null($jwt->getExpirationTime()) && time() > $jwt->getExpirationTime()) {
            throw new \Exception('The JWT has expired.');
        }
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception
     */
    protected function checkNotBefore(JWTInterface $jwt)
    {
        if (!is_null($jwt->getNotBefore()) && time() < $jwt->getNotBefore()) {
            throw new \Exception('The JWT has expired.');
        }
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception
     */
    protected function checkIssuedAt(JWTInterface $jwt)
    {
        if (!is_null($jwt->getIssuedAt()) && time() < $jwt->getIssuedAt()) {
            throw new \Exception('The JWT is issued in the futur.');
        }
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \Exception
     */
    protected function checkCritical(JWTInterface $jwt)
    {
        if (!is_null($jwt->getCritical())) {
            foreach ($jwt->getCritical() as $critical) {
                if (is_null($jwt->getHeaderValue($critical)) && is_null($jwt->getPayloadValue($critical))) {
                    throw new \Exception(sprintf("The claim/header '%s' is marked as critical but value is not set.", $critical));
                }
            }
        }
    }

    /**
     * @param $data
     *
     * @return array|mixed
     */
    protected function loadSerializedJsonJWS($data)
    {
        $encoded_payload = $data['payload'];
        $payload = Base64Url::decode($encoded_payload);

        $jws = array();
        foreach ($data['signatures'] as $signature) {
            if (array_key_exists('protected', $signature)) {
                $encoded_protected_header = $signature['protected'];
                $protected_header = json_decode(Base64Url::decode($encoded_protected_header), true);
            } else {
                $encoded_protected_header = null;
                $protected_header = array();
            }
            $unprotected_header = isset($signature['header']) ? $signature['header'] : array();

            $jws[] = $this->createJWS($encoded_protected_header.'.'.$encoded_payload, $protected_header, $unprotected_header, $payload, Base64Url::decode($signature['signature']));
        }

        return count($jws) > 1 ? $jws : current($jws);
    }

    /**
     * @param $input
     * @param $protected_header
     * @param $unprotected_header
     * @param $payload
     * @param $signature
     *
     * @return \Jose\JWSInterface
     *
     * @throws \Exception
     */
    protected function createJWS($input, $protected_header, $unprotected_header, $payload, $signature)
    {
        $complete_header = array_merge($protected_header, $unprotected_header);
        $this->convertJWTContent($complete_header, $payload);
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
        $complete_header = array();
        if ($protected_header !== null) {
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
     * @param $header
     *
     * @return \Jose\Operation\SignatureInterface|null
     */
    protected function getAlgorithm($header)
    {
        if (!array_key_exists('alg', $header)) {
            throw new \RuntimeException("The header parameter 'alg' is missing.");
        }
        $algorithm = $this->getJWAManager()->getAlgorithm($header['alg']);
        if (!$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException("The algorithm '".$header['alg']."' is not supported or does not implement SignatureInterface.");
        }

        return $algorithm;
    }

    /**
     * @param \Jose\JWAInterface                         $key_encryption_algorithm
     * @param \Jose\Operation\ContentEncryptionInterface $content_encryption_algorithm
     * @param \Jose\JWKInterface                         $key
     * @param                                            $encrypted_cek
     * @param array                                      $header
     *
     * @return mixed|string
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
        }
    }

    /**
     * @param array                 $data
     * @param \Jose\JWKSetInterface $jwk_set
     *
     * @return \Jose\JWEInterface|null
     */
    protected function loadSerializedJsonJWE($data, JWKSetInterface $jwk_set = null)
    {
        $ciphertext = Base64Url::decode($data['ciphertext']);
        if (array_key_exists('unprotected', $data)) {
            $unprotected_header = $data['unprotected'];
        } else {
            $unprotected_header = array();
        }
        $protected = array_key_exists('protected', $data) ? json_decode(Base64Url::decode($data['protected']), true) : array();
        $unprotected = array_key_exists('unprotected', $data) ? $data['unprotected'] : array();
        $aad = array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null;
        $tag = array_key_exists('tag', $data) ? Base64Url::decode($data['tag']) : null;
        $iv  = array_key_exists('iv', $data) ? Base64Url::decode($data['iv']) : null;

        foreach ($data['recipients'] as $recipient) {
            $encrypted_key = array_key_exists('encrypted_key', $recipient) ? Base64Url::decode($recipient['encrypted_key']) : null;
            $header = array_key_exists('header', $recipient) ? $recipient['header'] : array();
            $complete_header = array_merge($protected, $unprotected, $header);

            if (!array_key_exists('alg', $complete_header) || !array_key_exists('enc', $complete_header)) {
                throw new \InvalidArgumentException("Parameters 'enc' or 'alg' are missing.");
            }
            $keys = $jwk_set;
            if (is_null($keys)) {
                $keys = $this->getKeysFromCompleteHeader($complete_header);
            }
            $key_encryption_algorithm     = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
            $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['enc']);
            if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
                throw new \RuntimeException("The algorithm '".$complete_header['enc']."' does not implement ContentEncryptionInterface.");
            }
            if (!$key_encryption_algorithm instanceof DirectEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
                throw new \RuntimeException("The key encryption algorithm '".$complete_header['alg']."' is not supported or not a key encryption algorithm instance.");
            }

            foreach ($keys as $key) {
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $key, $encrypted_key, $complete_header);
                if ($cek !== null) {
                    $payload = $content_encryption_algorithm->decryptContent($ciphertext, $cek, $iv, $aad, $data['protected'], $tag);

                    if (array_key_exists('zip', $complete_header)) {
                        $method = $this->getCompressionManager()->getCompressionAlgorithm($complete_header['zip']);
                        if ($method === null) {
                            throw new \RuntimeException("Compression method '".$complete_header['zip']."' not supported");
                        }
                        $payload = $method->uncompress($payload);
                        if (!is_string($payload)) {
                            throw new \RuntimeException('Decompression failed');
                        }
                    }

                    $this->convertJWTContent($complete_header, $payload);

                    $jwe = $this->getJWTManager()->createJWE();
                    $jwe->setProtectedHeader($protected)
                        ->setUnprotectedHeader(array_merge($unprotected_header, $header))
                        ->setPayload($payload);

                    return $jwe;
                }
            }
        }
    }

    protected function getKeysFromCompleteHeader(array $header)
    {
        $keys = $this->getJWKSetManager()->createJWKSet();
        if (!is_null($jwk = $this->getJWKManager()->findByHeader($header))) {
            $keys->addKey($jwk);
        }
        if (!is_null($jwkset = $this->getJWKSetManager()->findByHeader($header))) {
            foreach ($jwkset as $key) {
                $keys->addKey($key);
            }
        }

        return $keys;
    }
}
