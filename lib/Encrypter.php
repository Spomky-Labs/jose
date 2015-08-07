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
use SpomkyLabs\Jose\Util\Converter;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class Encrypter implements EncrypterInterface
{
    use KeyChecker;

    /**
     * @return \SpomkyLabs\Jose\Payload\PayloadConverterManagerInterface
     */
    abstract protected function getPayloadConverter();

    /**
     * @return \Jose\JWTManagerInterface
     */
    abstract protected function getJWTManager();

    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    abstract protected function getJWKSetManager();

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
     * @param $input
     */
    private function checkInput(&$input)
    {
        if ($input instanceof JWTInterface) {
            return;
        }

        $header = array();
        $payload = $this->getPayloadConverter()->convertPayloadToString($header, $input);

        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload($payload)
            ->setProtectedHeader($header);
        $input = $jwt;
    }

    /**
     * @param array|JWKInterface|JWKSetInterface|JWTInterface|string $input
     * @param array                                                  $instructions
     * @param array                                                  $shared_protected_header
     * @param array                                                  $shared_unprotected_header
     * @param string                                                 $serialization
     * @param null                                                   $aad
     *
     * @return string
     */
    public function encrypt($input, array $instructions, array $shared_protected_header = array(), array $shared_unprotected_header = array(), $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $aad = null)
    {
        $this->checkInput($input);
        $this->checkInstructions($instructions, $serialization);

        $protected_header   = array_merge($input->getProtectedHeader(), $shared_protected_header);
        $unprotected_header = array_merge($input->getUnprotectedHeader(), $shared_unprotected_header);

        // We check if key management mode is OK
        $key_management_mode = $this->getKeyManagementMode($instructions, $protected_header, $unprotected_header);

        // We get the content encryption algorithm
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($instructions, $protected_header, $unprotected_header);

        // CEK
        $cek = $this->determineCEK($key_management_mode, $instructions, $protected_header, $unprotected_header, $content_encryption_algorithm->getCEKSize());

        $recipients = array('recipients' => array());
        foreach ($instructions as $instruction) {
            $recipients['recipients'][] = $this->computeRecipient($instruction, $protected_header, $unprotected_header, $cek, $content_encryption_algorithm->getCEKSize(), $serialization);
        }

        // We prepare the payload and compress it if required
        $payload = $input->getPayload();
        $compression_method = $this->findCompressionMethod($instructions, $protected_header, $unprotected_header);
        $this->compressPayload($payload, $compression_method);

        // We compute the initialization vector
        $iv = null;
        if (!is_null($iv_size = $content_encryption_algorithm->getIVSize())) {
            $iv = $this->createIV($iv_size);
        }

        // JWT Shared protected header
        $jwt_shared_protected_header = Base64Url::encode(json_encode($protected_header));

        // We encrypt the payload and get the tag
        $tag = null;
        $ciphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $jwt_shared_protected_header, $tag);

        // JWT Ciphertext
        $jwt_ciphertext = Base64Url::encode($ciphertext);

        // JWT AAD
        $jwt_aad = is_null($aad) ? null : Base64Url::encode($aad);

        // JWT Tag
        $jwt_tag = is_null($tag) ? null : Base64Url::encode($tag);

        // JWT IV
        $jwt_iv = is_null($iv) ? '' : Base64Url::encode($iv);

        $values = array(
            'ciphertext'    => $jwt_ciphertext,
            'protected'     => $jwt_shared_protected_header,
            'unprotected'   => $unprotected_header,
            'iv'            => $jwt_iv,
            'tag'           => $jwt_tag,
            'aad'           => $jwt_aad,
        );
        foreach ($values as $key => $value) {
            if (!empty($value)) {
                $recipients[$key] = $value;
            }
        }

        $prepared = Converter::convert($recipients, $serialization);

        return is_array($prepared) ? current($prepared) : $prepared;
    }

    /**
     * @param \Jose\EncryptionInstructionInterface $instruction
     * @param                                      $protected_header
     * @param                                      $unprotected_header
     * @param string                               $cek
     * @param int                                  $cek_size
     * @param string                               $serialization
     *
     * @return array
     *
     * @throws \Exception
     */
    protected function computeRecipient(EncryptionInstructionInterface $instruction, &$protected_header, $unprotected_header, $cek, $cek_size, $serialization)
    {
        if (!$this->checkKeyUsage($instruction->getRecipientKey(), 'encryption')) {
            throw new \InvalidArgumentException('Key cannot be used to sign');
        }

        $recipient_header   = $instruction->getRecipientUnprotectedHeader();
        $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header);

        $jwt_cek = null;
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            $jwt_cek = Base64Url::encode($key_encryption_algorithm->encryptKey($instruction->getRecipientKey(), $cek, $protected_header));
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            if (is_null($instruction->getSenderKey())) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            $additional_header_values = array();
            $jwt_cek = Base64Url::encode($key_encryption_algorithm->wrapAgreementKey($instruction->getSenderKey(), $instruction->getRecipientKey(), $cek, $cek_size, $complete_header, $additional_header_values));
            $this->updateHeader($additional_header_values, $protected_header, $recipient_header, $serialization);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            if (is_null($instruction->getSenderKey())) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            $additional_header_values = array();
            $jwt_cek = Base64Url::encode($key_encryption_algorithm->getAgreementKey($cek_size, $instruction->getSenderKey(), $instruction->getRecipientKey(), $complete_header, $additional_header_values));
            $this->updateHeader($additional_header_values, $protected_header, $recipient_header, $serialization);
        }

        $result = array();
        if (!is_null($jwt_cek)) {
            $result['encrypted_key'] = $jwt_cek;
        }
        if (!empty($recipient_header)) {
            $result['header'] = $recipient_header;
        }

        return $result;
    }

    /**
     * @param array  $additional_header_values
     * @param array  $protected_header
     * @param array  $recipient_header
     * @param string $serialization
     */
    protected function updateHeader(array $additional_header_values, array &$protected_header, array &$recipient_header, $serialization)
    {
        if (JSONSerializationModes::JSON_COMPACT_SERIALIZATION === $serialization) {
            $protected_header = array_merge($protected_header, $additional_header_values);
        } else {
            $recipient_header = array_merge($recipient_header, $additional_header_values);
        }
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     *
     * @return string
     */
    protected function getKeyManagementMode(array $instructions, $protected_header, $unprotected_header)
    {
        $mode = null;
        foreach ($instructions as $instruction) {
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);

            $temp = $this->getKeyManagementMode2($complete_header);
            if (is_null($mode)) {
                $mode = $temp;
            } else {
                if (!$this->areKeyManagementModeAuthorized($mode, $temp)) {
                    throw new \RuntimeException('Foreign key management mode forbidden.');
                }
            }
        }

        return $mode;
    }

    /**
     * @param string $mode1
     * @param string $mode2
     *
     * @return bool
     */
    protected function areKeyManagementModeAuthorized($mode1, $mode2)
    {
        if ($mode1 > $mode2) {
            $temp = $mode1;
            $mode1 = $mode2;
            $mode2 = $temp;
        }
        switch ($mode1.$mode2) {
            case 'encenc':
            case 'encwrap':
            case 'wrapwrap':
            case 'agreeagree':
            case 'dirdir':
                return true;
            default:
                return false;
        }
    }

    /**
     * @param array $complete_header
     *
     * @return string
     */
    protected function getKeyManagementMode2($complete_header)
    {
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header);

        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return 'enc';
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return 'wrap';
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return 'agree';
        } elseif ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return 'dir';
        } else {
            throw new \RuntimeException('Unable to get key management mode.');
        }
    }

    /**
     * @param string                                 $key_management_mode
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     * @param int                                    $cek_size
     *
     * @return string
     */
    protected function determineCEK($key_management_mode, array $instructions, $protected_header, $unprotected_header, $cek_size)
    {
        switch ($key_management_mode) {
            case 'enc':
            case 'wrap':
                return $this->createCEK($cek_size);
            case 'dir':
                return $this->getDirectKey($instructions, $protected_header, $unprotected_header);
            case 'agree':
                return $this->getAgreementKey($instructions, $protected_header, $unprotected_header, $cek_size);
            default:
                throw new \RuntimeException('Unable to get CEK (unsupported key management mode).');
        }
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     *
     * @return string
     */
    protected function getDirectKey(array $instructions, $protected_header, $unprotected_header)
    {
        $cek = null;
        foreach ($instructions as $instruction) {
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);

            $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header);
            if (!$key_encryption_algorithm instanceof DirectEncryptionInterface) {
                throw new \RuntimeException('The key encryption algorithm is not an instance of DirectEncryptionInterface');
            }

            $temp = $key_encryption_algorithm->getCEK($instruction->getRecipientKey(), $complete_header);
            if (is_null($cek)) {
                $cek = $temp;
            } else {
                if ($cek !== $temp) {
                    throw new \RuntimeException('Foreign CEK forbidden using direct key.');
                }
            }
        }

        return $cek;
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     * @param int                                    $cek_size
     *
     * @return string
     */
    protected function getAgreementKey(array $instructions, $protected_header, $unprotected_header, $cek_size)
    {
        $cek = null;
        foreach ($instructions as $instruction) {
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);

            $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_header);

            if (!$key_encryption_algorithm instanceof KeyAgreementInterface) {
                throw new \RuntimeException('The key encryption algorithm is not an instance of KeyAgreementInterface');
            }

            if (is_null($instruction->getSenderKey())) {
                throw new \RuntimeException('The sender key must be set using Key Agreement or Key Agreement with Wrapping algorithms.');
            }
            $additional_header_values = array();
            $temp = $key_encryption_algorithm->getAgreementKey($cek_size, $instruction->getSenderKey(), $instruction->getRecipientKey(), $complete_header, $additional_header_values);
            if (is_null($cek)) {
                $cek = $temp;
            } else {
                if ($cek !== $temp) {
                    throw new \RuntimeException('Foreign CEK forbidden using direct key agreement.');
                }
            }
        }

        return $cek;
    }

    /**
     * @param string $payload
     * @param string $method
     */
    protected function compressPayload(&$payload, $method = null)
    {
        if (!is_null($method)) {
            $compression_method = $this->getCompressionMethod($method);
            $payload = $compression_method->compress($payload);
            if (!is_string($payload)) {
                throw new \RuntimeException('Compression failed.');
            }
        }
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     *
     * @return string
     */
    protected function findCompressionMethod(array $instructions, $protected_header, $unprotected_header)
    {
        $method = null;
        $first = true;
        foreach ($instructions as $instruction) {
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);
            if ($first) {
                if (array_key_exists('zip', $complete_header)) {
                    $method = $complete_header['zip'];
                }
                $first = null;
            } else {
                if (array_key_exists('zip', $complete_header) && $method !== $complete_header['zip']) {
                    throw new \RuntimeException('Foreign compression method forbidden');
                }
            }
        }

        return $method;
    }

    /**
     * @param string $method
     *
     * @return \Jose\Compression\CompressionInterface
     */
    protected function getCompressionMethod($method)
    {
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        if (is_null($compression_method)) {
            throw new \RuntimeException(sprintf("Compression method '%s' not supported"), $method);
        }

        return $compression_method;
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param string                                 $serialization
     */
    protected function checkInstructions(array $instructions, $serialization)
    {
        if (empty($instructions)) {
            throw new \InvalidArgumentException('No instruction.');
        }
        if (count($instructions) > 1 && JSONSerializationModes::JSON_SERIALIZATION !== $serialization) {
            throw new \InvalidArgumentException('Only one instruction authorized when Compact or Flattened Serialization Overview is selected.');
        }
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof EncryptionInstructionInterface) {
                throw new \InvalidArgumentException('Bad instruction. Must implement EncryptionInstructionInterface.');
            }
        }
    }

    /**
     * @param array $complete_header
     *
     * @return \Jose\Operation\DirectEncryptionInterface|\Jose\Operation\KeyEncryptionInterface|\Jose\Operation\KeyAgreementInterface|\Jose\Operation\KeyAgreementWrappingInterface
     */
    protected function getKeyEncryptionAlgorithm($complete_header)
    {
        if (!array_key_exists('alg', $complete_header)) {
            throw new \RuntimeException("Parameter 'alg' is missing.");
        }
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header['alg']);
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
        throw new \RuntimeException(sprintf("The key encryption algorithm '%s' is not supported or not a key encryption algorithm instance.", $complete_header['alg']));
    }

    /**
     * @param \Jose\EncryptionInstructionInterface[] $instructions
     * @param array                                  $protected_header
     * @param array                                  $unprotected_header
     *
     * @return \Jose\Operation\ContentEncryptionInterface
     */
    protected function getContentEncryptionAlgorithm(array $instructions, array $protected_header = array(), array $unprotected_header = array())
    {
        $algorithm = null;
        foreach ($instructions as $instruction) {
            $recipient_header   = $instruction->getRecipientUnprotectedHeader();
            $complete_header    = array_merge($protected_header, $unprotected_header, $recipient_header);
            if (!array_key_exists('enc', $complete_header)) {
                throw new \InvalidArgumentException("Parameters 'enc' is missing.");
            }
            if (is_null($algorithm)) {
                $algorithm = $complete_header['enc'];
            } else {
                if ($algorithm !== $complete_header['enc']) {
                    throw new \InvalidArgumentException("Foreign 'enc' parameter forbidden.");
                }
            }
        }

        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
            throw new \RuntimeException(sprintf("The algorithm '%s' does not implement ContentEncryptionInterface.", $algorithm));
        }

        return $content_encryption_algorithm;
    }
}
