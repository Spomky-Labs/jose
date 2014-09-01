<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 * This class handles encryption of text using A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512 algorithms.
 */
abstract class AES implements JWKInterface, ContentEncryptionInterface, ContentDecryptionInterface
{
    public function toPublic()
    {
        return $this->getValues();
    }

    /**
     * @inheritdoc
     */
    public function encryptContent($input, $cek, $iv, array &$header = array())
    {
        $k = substr($cek, strlen($cek)/2);

        $aes = new \Crypt_AES();
        $aes->Crypt_Base(CRYPT_AES_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        return $aes->encrypt($input);
    }

    public function decryptContent($input, $cek, $iv, array $header)
    {
        $k = substr($cek, strlen($cek)/2);

        $aes = new \Crypt_AES();
        $aes->Crypt_Base(CRYPT_AES_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        return $aes->decrypt($input);
    }

    public function isPrivate()
    {
        return true;
    }

    public function isPublic()
    {
        return true;
    }

    public function calculateAuthenticationTag($cek, $iv, $encrypted_data, array $header)
    {
        $mac_key          = substr($cek, 0, strlen($cek)/2);
        $encoded_header   = Base64Url::encode(json_encode($header));
        $auth_data_length = strlen($encoded_header);

        $secured_input = implode('', array(
            $encoded_header,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8)
        ));
        $hash = hash_hmac($this->getHashAlgorithm($header), $secured_input, $mac_key, true);

        return substr($hash, 0, strlen($hash)/2);
    }

    public function checkAuthenticationTag($authentication_tag, $cek, $iv, $encrypted_data, array $header)
    {
        return $authentication_tag === $this->calculateAuthenticationTag($cek, $iv, $encrypted_data, $header);
    }

    /*public function createIV(array $header)
    {
        $enc = $this->getEncryptionAlgorithm($header);
        switch ($enc) {
            case 'A128CBC-HS256':
                $iv = $this->generateRandomString(128 / 8);
                break;
            case 'A192CBC-HS384':
                $iv = $this->generateRandomString(192 / 8);
                break;
            case 'A256CBC-HS512':
                $iv = $this->generateRandomString(256 / 8);
                break;
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
        $this->setValue('iv', $iv);

        return $this;
    }

    public function createCEK(array $header)
    {
        $enc = $this->getEncryptionAlgorithm($header);
        switch ($enc) {
            case 'A128CBC-HS256':
                $cek = $this->generateRandomString(256 / 8);
                break;
            case 'A192CBC-HS384':
                $cek = $this->generateRandomString(384 / 8);
                break;
            case 'A256CBC-HS512':
                $cek = $this->generateRandomString(512 / 8);
                break;
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
        $this->setValue('cek', $cek);

        return $this;
    }

    protected function generateRandomString($length)
    {
        return crypt_random_string($length);
    }*/

    protected function getEncryptionAlgorithm(array $header)
    {
        $enc = $header['enc'];
        $alg = $this->getValue('alg');
        if ($alg !== null && $alg === $enc) {
            throw new \Exception("The algorithm used by this key is '$alg', but the header tried to use '$enc'");
        }

        return $enc;
    }

    protected function getHashAlgorithm(array $header)
    {
        $enc = $this->getEncryptionAlgorithm($header);
        switch ($enc) {
            case 'A128CBC-HS256':
                return 'sha256';
            case 'A192CBC-HS384':
                return 'sha384';
            case 'A256CBC-HS512':
                return 'sha512';
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
    }
}
