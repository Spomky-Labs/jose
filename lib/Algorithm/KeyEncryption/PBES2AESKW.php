<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use PBKDF2\PBKDF2;
use Jose\JWKInterface;
use Base64Url\Base64Url;
use Jose\Operation\KeyEncryptionInterface;

abstract class PBES2AESKW implements KeyEncryptionInterface
{
    public function encryptKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($header);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = openssl_random_pseudo_bytes($key_size/8);
        $count = 4096;
        $password = Base64Url::decode($key->getValue("k"));

        // We set headers parameters
        $header["p2s"] = Base64Url::encode($salt);
        $header["p2c"] = $count;

        if (function_exists('hash_pbkdf2')) {
            $derived_key = hash_pbkdf2($hash_algorithm, $password, $header["alg"]."\x00".$salt, $count, $key_size, true);
        } else {
            $derived_key = PBKDF2::deriveKey($hash_algorithm, $password, $header["alg"]."\x00".$salt, $count, $key_size);
        }

        return $wrapper->wrap($derived_key, $cek);
    }

    public function decryptKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($header);
        $this->checkHeaderAdditionalParameters($header);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = $header["alg"]."\x00".Base64Url::decode($header["p2s"]);
        $count = $header["p2c"];
        $password = Base64Url::decode($key->getValue("k"));

        if (function_exists('hash_pbkdf2')) {
            $derived_key = hash_pbkdf2($hash_algorithm, $password, $salt, $count, $key_size, true);
        } else {
            $derived_key = PBKDF2::deriveKey($hash_algorithm, $password, $salt, $count, $key_size);
        }

        return $wrapper->unwrap($derived_key, $encryted_cek);
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("oct" !== $key->getKeyType() || null === $key->getValue("k")) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }

    protected function checkHeaderAlgorithm(array $header)
    {
        if (!isset($header["alg"]) || empty($header["alg"])) {
            throw new \InvalidArgumentException("The header parameter 'alg' is missing or invalid.");
        }
    }

    protected function checkHeaderAdditionalParameters(array $header)
    {
        if (!isset($header["p2s"]) || !isset($header["p2c"]) || empty($header["p2s"]) || empty($header["p2c"])) {
            throw new \InvalidArgumentException("The header is not valid. 'p2s' or 'p2c' parameter is missing or invalid.");
        }
    }

    abstract protected function getWrapper();
    abstract protected function getHashAlgorithm();
    abstract protected function getKeySize();
}
