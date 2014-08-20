<?php

namespace SpomkyLabs\JOSE\Encryption;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;
use SpomkyLabs\JOSE\JWKContentEncryptionInterface;
use SpomkyLabs\JOSE\JWKAuthenticationTagInterface;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 * This class handles encryption of text using A128CBC-HS256 or A256CBC-HS512 algorithms.
 */
class AES  implements JWKInterface, JWKEncryptInterface, JWKDecryptInterface, JWKContentEncryptionInterface, JWKAuthenticationTagInterface
{
    use JWK;
    protected $values = array('kty' => 'AES');

    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        return $this->getValues();
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data)
    {
        $k = substr($this->getValue('cek'), strlen($this->getValue('cek'))/2);

        $aes = new \Crypt_AES(CRYPT_AES_MODE_CBC);
        $aes->setBlockLength($this->getBlockLength());
        $aes->setKey($k);
        $aes->setIV($this->getValue(('iv')));

        return $aes->encrypt($data);
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data)
    {
        $k = substr($this->getValue('cek'), strlen($this->getValue('cek'))/2);

        $aes = new \Crypt_AES(CRYPT_AES_MODE_CBC);
        $aes->setBlockLength($this->getBlockLength());
        $aes->setKey($k);
        $aes->setIV($this->getValue(('iv')));

        return $aes->decrypt($data);
    }

    public function isPrivate()
    {
        return true;
    }

    protected function getBlockLength()
    {
        $enc = $this->getValue('enc');
        switch ($enc) {
            case 'A128CBC-HS256':
                return 128;
            case 'A192CBC-HS384':
                return 192;
            case 'A256CBC-HS512':
                return 256;
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
    }

    private function getHashAlgorithm()
    {
        $enc = $this->getValue('enc');
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

    public function calculateAuthenticationTag($data)
    {
        $mac_key          = substr($this->getValue('cek'), 0, strlen($this->getValue('cek'))/2);
        $auth_data        = Base64Url::encode(json_encode($data['header']));
        $auth_data_length = strlen($auth_data);

        $secured_input = implode('', array(
            $auth_data,
            $data['iv'],
            $data['encrypted_data'],
            // NOTE: PHP doesn't support 64bit big endian, so handling upper & lower 32bit.
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8)
        ));
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return substr($hash, 0, strlen($hash)/2);
    }

    public function checkAuthenticationTag($data)
    {
        return $data['authentication_tag'] === $this->calculateAuthenticationTag($data);
    }

    public function createIV()
    {
        $iv = null;
        $enc = $this->getValue('enc');
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

    public function createCEK()
    {
        $cek = null;
        $enc = $this->getValue('enc');
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

    /**
     * @param integer $length
     */
    private function generateRandomString($length)
    {
        return crypt_random_string($length);
    }
}
