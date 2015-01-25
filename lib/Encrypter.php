<?php

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;
use Jose\EncryptionInstructionInterface;
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

    public function encrypt($input, array $instructions, array $shared_protected_header = array(), array $shared_unprotected_header = array(), $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION, $aad = null)
    {
        $this->checkInput($input);
        if (empty($instructions)) {
                throw new \RuntimeException("No instruction.");
        }

        $protected_header   = array_merge($input->getProtectedHeader(), $shared_protected_header);
        $unprotected_header = array_merge($input->getUnprotectedHeader(), $shared_unprotected_header);
        $complete_header    = array_merge($protected_header, $unprotected_header);

        // Shared protected header
        $jwt_shared_protected_header = Base64Url::encode(json_encode($protected_header));

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

        // AAD
        $jwt_aad = null !== $aad?Base64Url::encode($aad):null;

        if (!array_key_exists("enc", $complete_header)) {
            throw new \RuntimeException("The parameter 'enc' is not defined in shared headers.");
        }
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header["enc"]);
        if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
            throw new \RuntimeException("The content encryption '".$complete_header["enc"]."' is not supported or not a ContentEncryptionInterface instance.");
        }

        // IV
        $iv = null;
        if (null !== $iv_size = $content_encryption_algorithm->getIVSize()) {
            $iv = $this->createIV($iv_size);
        }

        // CEK
        $cek = null;
        if (null !== $cek_size = $content_encryption_algorithm->getCEKSize()) {
            $cek = $this->createCEK($cek_size);
        }

        /*if ($jwt_header["alg"] === "dir") {
            $tmp = $instructions[0]['key'];
            $cek = $tmp->getValue("dir");
        } else {
            if ($key->getCEKSize($jwt_header) !== null) {
                $cek = $this->createCEK($key->getCEKSize($jwt_header));
            }
        }*/

        $tag = null;

        // Cyphertext
        $cyphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $protected_header, $tag);
        $jwt_cyphertext = Base64Url::encode($cyphertext);

        // Tag
        $jwt_tag = null !== $tag?Base64Url::encode($tag):null;

        $recipients = array();

        /*foreach ($instructions as $instruction) {
            if (!$instruction instanceof SignatureInstructionInterface) {
                    throw new \RuntimeException("Bad instruction. Must implement SignatureInstructionInterface.");
            }
            $jwk = $instruction['key'];
            $complete_header = $jwt_header;
            if (isset($instruction['header'])) {
                $complete_header = array_merge($complete_header, $instruction['header']);
            }

            $tmp = array(
                "encrypted_key" => $jwk->encryptKey($jwt_cek, $protected_header, $sender_key),
            );
            if (isset($instruction['header'])) {
                $tmp["header"] = $instruction['header'];
            }
            if ($sender_key instanceof JWKAgreementKeyExtension) {
                if ($compact === false) {
                    if (!isset($tmp['header'])) {
                        $tmp['header'] = array();
                    }
                    $tmp["header"] += $sender_key->getAgreementKey();
                } else {
                    $protected_header += $sender_key->getAgreementKey();
                }
            }
            $recipients[] = $tmp;
        }

        if (count($recipients) === 0) {
            throw new \RuntimeException("No recipient");
        }

        if (count($recipients) > 1 && $compact === true) {
            throw new \RuntimeException("Can not compact when using multiple recipients");
        }

        $jwt_tag = $key->calculateAuthenticationTag($jwt_cek, $jwt_iv, $encrypted_data, $protected_header);

        if (count($recipients) === 1 && $compact === true) {
            return implode(".", array(
                Base64Url::encode(json_encode($protected_header)),
                Base64Url::encode($recipients[0]['encrypted_key']),
                Base64Url::encode($jwt_iv),
                Base64Url::encode($encrypted_data),
                Base64Url::encode($jwt_tag),
            ));
        }

        return json_encode(array(
            "protected" => Base64Url::encode(json_encode($protected_header)),
            "unprotected" => $unprotected_header,
            "iv" => Base64Url::encode($jwt_iv),
            "ciphertext" => Base64Url::encode($encrypted_data),
            "tag" => Base64Url::encode($jwt_tag),
            "recipients" => $recipients,
        ));*/
    }

    /**
     * @param string $encrypted_cek
     */
    public function getCEK(array $instructions, array $header)
    {
        $random_cek = true;
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof EncryptionInstructionInterface) {
                throw new \RuntimeException("Bad instruction. Must implement EncryptionInstructionInterface.");
            }
            $complete_header = array_merge($header, );
            $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header);
            if ($key_encryption_algorithm instanceof DirectEncryptionInterface || $key_encryption_algorithm instanceof KeyAgreementInterface) {
                $random_cek = false;
                break;
            }
        }
    }

    public function checkInput(&$input)
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
            $jwt->setPayload(json_encode($input->getPayload()));

            return;
        }
        if (is_string($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload($input);

            return;
        }
        if (!$input instanceof JWTInterface) {
            throw new \InvalidArgumentException("Unsupported input type");
        }
    }
}
