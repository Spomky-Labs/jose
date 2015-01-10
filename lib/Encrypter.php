<?php

namespace SpomkyLabs\Jose;

use SpomkyLabs\Jose\Util\Base64Url;
use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class Encrypter implements EncrypterInterface
{
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
     * @param  integer $size The size of the CEK in bytes
     * @return string
     */
    abstract protected function createCEK($size);

    /**
     * @param  integer $size The size of the IV in bytes
     * @return string
     */
    abstract protected function createIV($size);

    //public function encryptAndConvert($compact, $input, array $operation_keys, array $protected_header = array(), array $unprotected_header = array(), JWKInterface $sender_key = null)
    public function encrypt($input, JWKSetInterface $keys, JWKInterface $sender_key = null, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION)
    {
        if ($compact === false) {
            throw new \Exception("JSON Serialized representation is not supported");
        }

        if (is_array($input)) {
            $input = json_encode($input);
        } elseif ($input instanceof JWKInterface || $input instanceof JWKSetInterface) {
            $protected_header['cty'] = $input instanceof JWKInterface ? 'jwk+json' : 'jwkset+json';
            $input = json_encode($input);
        }
        if (!is_string($input)) {
            throw new \Exception("Unsupported input type");
        }

        $jwt_header = array();
        if ($protected_header !== null) {
            $jwt_header = array_merge($jwt_header, $protected_header);
        }
        if ($unprotected_header !== null) {
            $jwt_header = array_merge($jwt_header, $unprotected_header);
        }

        //When using not compact format, we must determine the key management mode first

        $type = $this->getJWKManager()->getType($jwt_header['enc']);
        $key = $this->getJWKManager()->createJWK(array(
            "kty" => $type,
        ));

        if (!$key instanceof ContentEncryptionInterface) {
            throw new \Exception("The content encryption algorithm is not valid");
        }

        if (isset($jwt_header['zip'])) {
            $method = $this->getCompressionManager()->getCompressionAlgorithm($jwt_header['zip']);
            if ($method === null) {
                throw new \Exception("Compression method '".$jwt_header['zip']."' not supported");
            }
            $input = $method->compress($input);
            if (!is_string($input)) {
                throw new \Exception("Compression failed");
            }
        }

        $jwt_iv = null;
        if ($key->getIVSize($jwt_header) !== null) {
            $jwt_iv = $this->createIV($key->getIVSize($jwt_header));
        }

        $jwt_cek = null;
        if ($jwt_header["alg"] === "dir") {
            $tmp = $operation_keys[0]['key'];
            $jwt_cek = $tmp->getValue("dir");
        } else {
            if ($key->getCEKSize($jwt_header) !== null) {
                $jwt_cek = $this->createCEK($key->getCEKSize($jwt_header));
            }
        }

        $encrypted_data = $key->encryptContent($input, $jwt_cek, $jwt_iv, $jwt_header);

        $recipients = array();

        foreach ($operation_keys as $operation_key) {
            $jwk = $operation_key['key'];
            /*$complete_header = $jwt_header;
            if (isset($operation_key['header'])) {
                $complete_header = array_merge($complete_header, $operation_key['header']);
            }*/

            $tmp = array(
                "encrypted_key" => $jwk->encryptKey($jwt_cek, $protected_header, $sender_key),
            );
            if (isset($operation_key['header'])) {
                $tmp["header"] = $operation_key['header'];
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
            throw new \Exception("No recipient");
        }

        if (count($recipients) > 1 && $compact === true) {
            throw new \Exception("Can not compact when using multiple recipients");
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
        ));
    }
}
