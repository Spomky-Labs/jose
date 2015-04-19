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
     * @param int $size The size of the CEK in bits
     *
     * @return string
     */
    abstract protected function createCEK($size);

    /**
     * @param int $size The size of the IV in bits
     *
     * @return string
     */
    abstract protected function createIV($size);

    /**
     * @param array|JWKInterface|JWKSetInterface|JWTInterface|string $input
     * @param array                                                  $instructions
     * @param array                                                  $shared_protected_header
     * @param array                                                  $shared_unprotected_header
     * @param string                                                 $serialization
     * @param null                                                   $aad
     *
     * @return array|mixed
     */
    public function encrypt($input, array $instructions, array $shared_protected_header = array(), array $shared_unprotected_header = array(), $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $aad = null)
    {
        if (JSONSerializationModes::JSON_SERIALIZATION === $serialization) {
            throw new \RuntimeException('JSON serialization not yet supported.');
        }
        $this->checkInput($input);
        $this->checkInstructions($instructions);

        $protected_header   = array_merge($input->getProtectedHeader(), $shared_protected_header);
        $unprotected_header = array_merge($input->getUnprotectedHeader(), $shared_unprotected_header);

        // AAD
        $jwt_aad = is_null($aad) ? null : Base64Url::encode($aad);

        $recipients = array();
        foreach ($instructions as $instruction) {
            $recipients[] = $this->computeCEKEncryption($instruction, $input, $protected_header, $unprotected_header, $serialization, $aad, $jwt_aad);
        }

        return count($recipients) === 1 ? current($recipients) : $recipients;
    }

    protected function computeCEKEncryption(EncryptionInstructionInterface $instruction, JWTInterface $input, $protected_header, $unprotected_header, $serialization, $aad, $jwt_aad)
    {
        $recipient_header   = $instruction->getRecipientUnprotectedHeader();
        $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);
        $this->checkCompleteHeader($complete_header);

        $payload = $input->getPayload();
        $this->compressPayload($payload, $complete_header);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header['alg']);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_header['enc']);

        // IV
        $iv = null;
        if (!is_null($iv_size = $content_encryption_algorithm->getIVSize())) {
            $iv = $this->createIV($iv_size);
        }
        $jwt_iv = Base64Url::encode($iv);

        // CEK
        $cek     = null;
        $jwt_cek = null;
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            $cek = $this->createCEK($content_encryption_algorithm->getCEKSize());
            $jwt_cek = Base64Url::encode($key_encryption_algorithm->encryptKey($instruction->getRecipientKey(), $cek, $protected_header));
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            if (is_null($instruction->getSenderKey())) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            $cek = $this->createCEK($content_encryption_algorithm->getCEKSize());
            if (JSONSerializationModes::JSON_COMPACT_SERIALIZATION === $serialization) {
                $jwt_cek = Base64Url::encode($key_encryption_algorithm->wrapAgreementKey($instruction->getSenderKey(), $instruction->getRecipientKey(), $cek, $content_encryption_algorithm->getCEKSize(), $complete_header, $protected_header));
            } else {
                $jwt_cek = Base64Url::encode($key_encryption_algorithm->wrapAgreementKey($instruction->getSenderKey(), $instruction->getRecipientKey(), $cek, $content_encryption_algorithm->getCEKSize(), $complete_header, $recipient_header));
            }
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            if (is_null($instruction->getSenderKey())) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            if (JSONSerializationModes::JSON_COMPACT_SERIALIZATION === $serialization) {
                $cek = $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $instruction->getSenderKey(), $instruction->getRecipientKey(), $complete_header, $protected_header);
            } else {
                $cek = $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $instruction->getSenderKey(), $instruction->getRecipientKey(), $complete_header, $recipient_header);
            }
            $jwt_cek = '';
        } elseif ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            $cek = $key_encryption_algorithm->getCEK($instruction->getRecipientKey(), array());
            $jwt_cek = '';
        }

        // Shared protected header
        $jwt_shared_protected_header = Base64Url::encode(json_encode($protected_header));

        // Cyphertext
        $tag = null;
        $cyphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $jwt_shared_protected_header, $tag);
        $jwt_cyphertext = Base64Url::encode($cyphertext);

        // Tag
        $jwt_tag = is_null($tag) ? null : Base64Url::encode($tag);

        $result = array(
            'ciphertext' => $jwt_cyphertext,
        );
        $values = array(
            'protected'     => $jwt_shared_protected_header,
            'unprotected'   => $unprotected_header,
            'header'        => $recipient_header,
            'iv'            => $jwt_iv,
            'tag'           => $jwt_tag,
            'aad'           => $jwt_aad,
            'encrypted_key' => $jwt_cek,
        );
        foreach ($values as $key => $value) {
            if (!empty($value)) {
                $result[$key] = $value;
            }
        }
        $prepared = Converter::convert($result, $serialization);

        return is_array($prepared) && count($prepared) === 1 ? current($prepared) : $prepared;
    }

    /**
     * @param array $complete_header
     *
     * @throws \InvalidArgumentException
     */
    protected function checkCompleteHeader(array $complete_header)
    {
        foreach (array('enc', 'alg') as $key) {
            if (!array_key_exists($key, $complete_header)) {
                throw new \InvalidArgumentException(sprintf("Parameters '%s' is missing.", $key));
            }
        }
    }

    protected function compressPayload(&$payload, array $complete_header)
    {
        if (array_key_exists('zip', $complete_header)) {
            $compression_method = $this->getCompressionMethod($complete_header['zip']);
            $payload = $compression_method->compress($payload);
            if (!is_string($payload)) {
                throw new \RuntimeException('Compression failed.');
            }
        }
    }

    protected function getCompressionMethod($method)
    {
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        if (is_null($compression_method)) {
            throw new \RuntimeException(sprintf("Compression method '%s' not supported"), $method);
        }

        return $compression_method;
    }

    protected function checkInstructions(array $instructions)
    {
        if (empty($instructions)) {
            throw new \InvalidArgumentException('No instruction.');
        }
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof EncryptionInstructionInterface) {
                throw new \InvalidArgumentException('Bad instruction. Must implement EncryptionInstructionInterface.');
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
        foreach (array(
                     '\Jose\Operation\DirectEncryptionInterface',
                     '\Jose\Operation\KeyEncryptionInterface',
                     '\Jose\Operation\KeyAgreementInterface',
                     '\Jose\Operation\KeyAgreementWrappingInterface',
                 ) as $class) {
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
}
