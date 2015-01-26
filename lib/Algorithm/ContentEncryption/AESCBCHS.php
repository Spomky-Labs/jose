<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

use Jose\Operation\ContentEncryptionInterface;
use Base64Url\Base64Url;

/**
 *
 */
abstract class AESCBCHS implements ContentEncryptionInterface
{
    public function __construct()
    {
        if (!class_exists("\Crypt_AES")) {
            throw new \RuntimeException("The library 'phpseclib/phpseclib' is required to use AES based (except AES-GCM based) algorithms");
        }
    }

    /**
     * @inheritdoc
     */
    public function encryptContent($input, $cek, $iv, $aad, array &$header, &$tag)
    {
        $k = substr($cek, strlen($cek)/2);
        $calculated_aad = Base64Url::encode(json_encode($header));
        if (null !== $aad) {
            $calculated_aad .= $aad;
        }

        $aes = new \Crypt_AES();
        $aes->Crypt_Base(CRYPT_AES_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        $cyphertext = $aes->encrypt($input);
        $tag = $this->calculateAuthenticationTag($cyphertext, $cek, $iv, $calculated_aad);

        return $cyphertext;
    }

    public function decryptContent($input, $cek, $iv, $aad, array $header, $tag)
    {
        $encoded_header = Base64Url::encode(json_encode($header));
        $this->checkAuthenticationTag($input, $cek, $iv, $encoded_header, $tag);
        $k = substr($cek, strlen($cek)/2);

        $aes = new \Crypt_AES();
        $aes->Crypt_Base(CRYPT_AES_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        return $aes->decrypt($input);
    }

    protected function calculateAuthenticationTag($encrypted_data, $cek, $iv, $encoded_header)
    {
        $mac_key          = substr($cek, 0, strlen($cek)/2);
        $auth_data_length = strlen($encoded_header);

        $secured_input = implode('', array(
            $encoded_header,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8), // str_pad(dechex($auth_data_length), 4, "0", STR_PAD_LEFT)
        ));
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return substr($hash, 0, strlen($hash)/2);
    }

    /**
     * @param string $authentication_tag
     * @param string $encoded_header
     */
    protected function checkAuthenticationTag($encrypted_data, $cek, $iv, $encoded_header, $authentication_tag)
    {
        return $authentication_tag === $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $encoded_header);
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
    abstract protected function getKeySize();

    public function getIVSize()
    {
        return $this->getKeySize();
    }

    public function getCEKSize()
    {
        return $this->getKeySize();
    }
}
