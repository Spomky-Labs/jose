<?php

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
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
 * Class able to load JWS or JWT.
 */
abstract class Loader implements LoaderInterface
{
    use PayloadConverter;

    /**
     * The audience
     *
     * @return string
     */
    abstract protected function getAudience();

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
        $json = $this->convertInputToSerializedJson($input);
        if (array_key_exists("signatures", $json)) {
            return $this->loadSerializedJsonJWS($json);
        }
        if (array_key_exists("recipients", $json)) {
            return $this->loadSerializedJsonJWE($json, $jwk_set);
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * {@inheritdoc}
     */
    public function verifySignature(JWSInterface $jws, JWKSetInterface $jwk_set = null)
    {
        $complete_header = array_merge($jws->getProtectedHeader(), $jws->getUnprotectedHeader());
        if (null === $jwk_set) {
            $jwk_set = $this->getJWKManager()->findByHeader($complete_header);
        }

        if (empty($jwk_set)) {
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
        if (null !== $jwt->getExpirationTime() && time() > $jwt->getExpirationTime()) {
            return false;
        }
        if (null !== $jwt->getNotBefore() && time() < $jwt->getNotBefore()) {
            return false;
        }
        if (null !== $jwt->getIssuedAt() && time() < $jwt->getIssuedAt()) {
            return false;
        }
        if (null !== $jwt->getAudience() && $this->getAudience() !== $jwt->getAudience()) {
            return false;
        }
        if (null !== $jwt->getCritical()) {
            foreach ($jwt->getCritical() as $crit) {
                if (null === $jwt->getHeaderValue($crit) && null === $jwt->getPayloadValue($crit)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * @param $input
     * @return array|string
     */
    protected function convertInputToSerializedJson($input)
    {
        //We try to identify if the data is a JSON object. In this case, we consider that data is a JSON (Flattened) Seralization object
        if (is_array($data = json_decode($input, true))) {
            return $this->loadSerializedJson($data);
        }

        //Else, we consider that data is a JSON Compact Serialized object
        return $this->loadCompactSerializedJson($input);
    }

    /**
     * @param array $input
     */
    protected function loadSerializedJson($input)
    {
        if (array_key_exists("signatures", $input) || array_key_exists("recipients", $input)) {
            //The input is a Serialized Json Object
            return $input;
        } elseif (array_key_exists("signature", $input)) {
            //The input is a JWS Serialized Flattened Json Object
            $jws = array(
                "payload" => $input["payload"],
            );
            $signature = array();
            foreach (array("signature", "protected", "header") as $key) {
                if (array_key_exists($key, $input)) {
                    $signature[$key] = $input[$key];
                }
            }
            $jws["signatures"] = array($signature);

            return $jws;
        } elseif (array_key_exists("encrypted_key", $input)) {
            //The input is a JWE Serialized Flattened Json Object
            $jwe = array(
                "encrypted_key" => $input["encrypted_key"],
            );
            foreach (array("ciphertext", "protected", "unprotected", "aad", "iv", "tag") as $key) {
                if (array_key_exists($key, $input)) {
                    $jwe[$key] = $input[$key];
                }
            }
            $recipient = array("encrypted_key" => $input["encrypted_key"]);
            if (array_key_exists("header", $input)) {
                $recipient["header"] = $input["header"];
            }
            $jwe["recipients"] = array($recipient);

            return $jwe;
        }
    }

    /**
     * @param string $input
     */
    protected function loadCompactSerializedJson($input)
    {
        $parts = explode('.', $input);

        switch (count($parts)) {
            case 3:
                // We suppose it is a JWS Serialized Compact Json Object
                $input = array(
                    "payload" => $parts[1],
                    "signatures" => array(
                        array(
                            "protected" => $parts[0],
                            "signature" => $parts[2],
                        ),
                    ),
                );

                return $input;
            case 5:
                // We suppose it is a JWE Serialized Compact Json Object
                $input = array(
                    "protected" => $parts[0],
                    "recipients" => array(
                        array(
                            "encrypted_key" => $parts[1],
                        ),
                    ),
                    "iv" => $parts[2],
                    "ciphertext" => $parts[3],
                    "tag" => $parts[4],
                );

                return $input;
            default:
                throw new \InvalidArgumentException('Unable to load the input');
        }
    }

    /**
     * @param array $data
     */
    protected function loadSerializedJsonJWS($data)
    {
        $encoded_payload = $data['payload'];
        $payload = Base64Url::decode($encoded_payload);

        $jws = array();
        foreach ($data['signatures'] as $signature) {
            if (array_key_exists("protected", $signature)) {
                $encoded_protected_header = $signature['protected'];
                $protected_header = json_decode(Base64Url::decode($encoded_protected_header), true);
            } else {
                $encoded_protected_header = null;
                $protected_header = array();
            }
            $unprotected_header = isset($signature['header']) ? $signature['header'] : array();

            $jws[] = $this->createJWS($encoded_protected_header.".".$encoded_payload, $protected_header, $unprotected_header, $payload, Base64Url::decode($signature["signature"]));
        }

        return count($jws)>1 ? $jws : current($jws);
    }

    /**
     * @param string $payload
     */
    protected function createJWS($input, $protected_header, $unprotected_header, $payload, $signature)
    {
        $complete_header = array_merge($protected_header, $unprotected_header);
        $this->convertJWTContent($complete_header, $payload);
        $jws = $this->getJWTManager()->createJWS();
        $jws->setPayload($payload)
            ->setInput($input)
            ->setSignature($signature);
        if (!empty($protected_header)) {
            $jws->setProtectedHeader($protected_header);
        }
        if (!empty($unprotected_header)) {
            $jws->setUnprotectedHeader($unprotected_header);
        }

        return $jws;
    }

    /**
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
     */
    protected function getAlgorithm($header)
    {
        if (!array_key_exists("alg", $header)) {
            throw new \RuntimeException("The header parameter 'alg' is missing.");
        }
        $algorithm = $this->getJWAManager()->getAlgorithm($header["alg"]);
        if (null === $algorithm || !$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException("The algorithm '".$header["alg"]."' is not supported or does not implement SignatureInterface.");
        }

        return $algorithm;
    }

    /**
     * @param string $encrypted_cek
     */
    public function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionInterface $content_encryption_algorithm, JWKInterface $key, $encrypted_cek, array $header)
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key, $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey($key, $content_encryption_algorithm->getCEKSize(), $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $encrypted_cek, $content_encryption_algorithm->getCEKSize(), $header);
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey($key, $encrypted_cek, $header);
        }
    }

    /**
     * @param array $data
     */
    protected function loadSerializedJsonJWE($data, JWKSetInterface $jwk_set = null)
    {
        $ciphertext = Base64Url::decode($data['ciphertext']);
        if (array_key_exists("unprotected", $data)) {
            $unprotected_header = $data['unprotected'];
        } else {
            $unprotected_header = array();
        }
        $protected = array_key_exists("protected", $data) ? json_decode(Base64Url::decode($data['protected']), true) : array();
        $unprotected = array_key_exists("unprotected", $data) ? $data['unprotected'] : array();
        $aad = array_key_exists("aad", $data) ? Base64Url::decode($data['aad']) : null;
        $tag = array_key_exists("tag", $data) ? Base64Url::decode($data['tag']) : null;
        $iv  = array_key_exists("iv", $data) ? Base64Url::decode($data['iv']) : null;

        foreach ($data['recipients'] as $recipient) {
            $encrypted_key = Base64Url::decode($recipient['encrypted_key']);
            $header = array_key_exists("header", $recipient) ? $recipient['header'] : array();
            $complete_header = array_merge($protected, $unprotected, $header);

            if (!array_key_exists("alg", $complete_header) || !array_key_exists("enc", $complete_header)) {
                throw new \InvalidArgumentException("Parameters 'enc' or 'alg' are missing.");
            }
            $keys = $jwk_set;
            if (null === $keys) {
                $keys = $this->getJWKManager()->findByHeader($complete_header);
            }
            $key_encryption_algorithm     = $this->getJWAManager()->getAlgorithm($complete_header["alg"]);
            $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header["enc"]);
            if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
                throw new \RuntimeException("The algorithm '".$complete_header["enc"]."' does not implement ContentEncryptionInterface.");
            }
            if (!$key_encryption_algorithm instanceof DirectEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
                throw new \RuntimeException("The key encryption algorithm '".$complete_header["alg"]."' is not supported or not a key encryption algorithm instance.");
            }

            foreach ($keys as $key) {
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $key, $encrypted_key, $complete_header);
                if ($cek !== null) {
                    $payload = $content_encryption_algorithm->decryptContent($ciphertext, $cek, $iv, $aad, $complete_header, $tag);

                    if (array_key_exists("zip", $complete_header)) {
                        $method = $this->getCompressionManager()->getCompressionAlgorithm($complete_header['zip']);
                        if ($method === null) {
                            throw new \RuntimeException("Compression method '".$complete_header['zip']."' not supported");
                        }
                        $payload = $method->uncompress($payload);
                        if (!is_string($payload)) {
                            throw new \RuntimeException("Decompression failed");
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
}
