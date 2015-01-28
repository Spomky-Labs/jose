<?php

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;
use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;
use Jose\EncryptionInstructionInterface;
use Jose\Operation\KeyEncryptionInterface;
use Jose\Operation\DirectEncryptionInterface;
use Jose\Operation\KeyAgreementInterface;
use Jose\Operation\KeyAgreementWrappingInterface;
use Jose\Operation\ContentEncryptionInterface;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class Encrypter implements EncrypterInterface
{
    /**
     * @return \Jose\JWTManagerInterface
     */
    abstract protected function getJWTManager();

    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    /**
     * @return \Jose\Compression\CompressionManagerInterface
     */
    abstract protected function getCompressionManager();

    /**
     * @param  integer $size The size of the CEK in bits
     * @return string
     */
    abstract protected function createCEK($size);

    /**
     * @param  integer $size The size of the IV in bits
     * @return string
     */
    abstract protected function createIV($size);

    /**
     * @param  array|JWKInterface|JWKSetInterface|JWTInterface|string $input
     * @param  array                                                  $instructions
     * @param  array                                                  $shared_protected_header
     * @param  array                                                  $shared_unprotected_header
     * @param  string                                                 $serialization
     * @param  null                                                   $aad
     * @return array|mixed
     */
    public function encrypt($input, array $instructions, array $shared_protected_header = array(), array $shared_unprotected_header = array(), $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $aad = null)
    {
        if (JSONSerializationModes::JSON_SERIALIZATION === $serialization) {
            throw new \RuntimeException("JSON serialization not yet supported.");
        }
        $this->checkInput($input);
        if (empty($instructions)) {
            throw new \RuntimeException("No instruction.");
        }

        // AAD
        $jwt_aad = null !== $aad ? Base64Url::encode($aad) : null;

        $recipients = array();
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof EncryptionInstructionInterface) {
                throw new \RuntimeException("Bad instruction. Must implement EncryptionInstructionInterface.");
            }

            $protected_header   = array_merge($input->getProtectedHeader(), $shared_protected_header);
            $unprotected_header = array_merge($input->getUnprotectedHeader(), $shared_unprotected_header, $instruction->getRecipientUnprotectedHeader());
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);

            $payload = $input->getPayload();
            if (array_key_exists("zip", $complete_header)) {
                $method = $this->getCompressionManager()->getCompressionAlgorithm($complete_header['zip']);
                if ($method === null) {
                    throw new \RuntimeException("Compression method '".$complete_header['zip']."' not supported.");
                }
                $payload = $method->compress($payload);
                if (!is_string($payload)) {
                    throw new \RuntimeException("Compression failed.");
                }
            }

            if (!array_key_exists("enc", $complete_header)) {
                throw new \RuntimeException("The parameter 'enc' is not defined in shared headers.");
            }
            $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header["enc"]);
            if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
                throw new \RuntimeException("The content encryption algorithm '".$complete_header["enc"]."' is not supported or not a ContentEncryptionInterface instance.");
            }

            if (!array_key_exists("alg", $complete_header)) {
                throw new \RuntimeException("The parameter 'alg' is not defined in shared headers.");
            }
            $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header["alg"]);
            if (!$key_encryption_algorithm instanceof DirectEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyEncryptionInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementInterface &&
                !$key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
                throw new \RuntimeException("The key encryption algorithm '".$complete_header["alg"]."' is not supported or not a key encryption algorithm instance.");
            }

            // IV
            $iv = null;
            if (null !== $iv_size = $content_encryption_algorithm->getIVSize()) {
                $iv = $this->createIV($iv_size);
            }
            $jwt_iv = Base64Url::encode($iv);

            // CEK
            $cek     = null;
            $jwt_cek = null;
            if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
                $cek = $this->createCEK($content_encryption_algorithm->getCEKSize());
                $jwt_cek = Base64Url::encode($key_encryption_algorithm->encryptKey($instruction->getRecipientPublicKey(), $cek, $protected_header));
            } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
                if (null === $instruction->getSenderPrivateKey()) {
                    throw new \RuntimeException("The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.");
                }
                $cek = $this->createCEK($content_encryption_algorithm->getCEKSize());
                $jwt_cek = Base64Url::encode($key_encryption_algorithm->wrapAgreementKey($instruction->getSenderPrivateKey(), $instruction->getRecipientPublicKey(), $cek, $content_encryption_algorithm->getCEKSize(), $protected_header));
            } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
                if (null === $instruction->getSenderPrivateKey()) {
                    throw new \RuntimeException("The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.");
                }
                $cek = $key_encryption_algorithm->setAgreementKey($instruction->getSenderPrivateKey(), $instruction->getRecipientPublicKey(), $content_encryption_algorithm->getCEKSize(), $protected_header);
                $jwt_cek = "";
            } elseif ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
                $cek = $key_encryption_algorithm->getCEK($instruction->getRecipientPublicKey(), array());
                $jwt_cek = "";
            }

            // Shared protected header
            $jwt_shared_protected_header = Base64Url::encode(json_encode($protected_header));

            // Cyphertext
            $tag = null;
            $cyphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $protected_header, $tag);
            $jwt_cyphertext = Base64Url::encode($cyphertext);

            // Tag
            $jwt_tag = null !== $tag ? Base64Url::encode($tag) : null;

            switch ($serialization) {
                case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                    $recipients[] = "{$jwt_shared_protected_header}.{$jwt_cek}.{$jwt_iv}.{$jwt_cyphertext}.{$jwt_tag}";
                    break;
                case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                    $result = array(
                        "ciphertext" => $jwt_cyphertext,
                    );
                    $values = array(
                        "protected"     => $jwt_shared_protected_header,
                        "unprotected"   => $unprotected_header,
                        "header"        => $recipient_header,
                        "iv"            => $jwt_iv,
                        "tag"           => $jwt_tag,
                        "aad"           => $jwt_aad,
                        "encrypted_key" => $jwt_cek,
                    );
                    foreach ($values as $key => $value) {
                        if (!empty($value)) {
                            $result[$key] = $value;
                        }
                    }
                    $recipients[] = json_encode($result);
                    break;

                default:
                    throw new \RuntimeException("Unsupported serialization mode.");
            }
        }

        return count($recipients) === 1 ? current($recipients) : $recipients;
    }

    /**
     * @param $input
     */
    private function checkInput(&$input)
    {
        if ($input instanceof JWKInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                  ->setProtectedHeaderValue("cty", "jwk+json");
            $input = $jwt;

            return;
        }
        if ($input instanceof JWKSetInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                  ->setProtectedHeaderValue("cty", "jwkset+json");
            $input = $jwt;

            return;
        }
        if (is_array($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input));
            $input = $jwt;

            return;
        }
        if (is_string($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload($input);
            $input = $jwt;

            return;
        }
        if (!$input instanceof JWTInterface) {
            throw new \InvalidArgumentException("Unsupported input type");
        }
    }
}
