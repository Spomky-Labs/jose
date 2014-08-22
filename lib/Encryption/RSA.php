<?php

namespace SpomkyLabs\JOSE\Encryption;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;
use SpomkyLabs\JOSE\Util\RSAConverter;

/**
 * This class handles encryption of CEK using RSA, RSA-OAEP or RSA-OAEP-256.
 */
class RSA implements JWKInterface, JWKEncryptInterface, JWKDecryptInterface
{
    use JWK;

    protected $values = array('kty' => 'RSA');

    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        $values = $this->getValues();

        $keys = array('p', 'd', 'q', 'dp', 'dq', 'qi');
        foreach ($keys as $key) {
            if ( isset($values[$key])) {
                unset($values[$key]);
            }
        }

        return $values;
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data, array &$header = array())
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(false));

        if ($this->getEncryptionMethod() === CRYPT_RSA_ENCRYPTION_OAEP) {
            $rsa->setHash($this->getHashAlgorithm());
            $rsa->setMGFHash($this->getHashAlgorithm());
        }
        $rsa->setEncryptionMode($this->getEncryptionMethod());

        return $rsa->encrypt($data);
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data, array $header = array())
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));
        if (!$this->isPrivate()) {
            throw new \Exception("The private key is missing");
        }

        if ($this->getEncryptionMethod() === CRYPT_RSA_ENCRYPTION_OAEP) {
            $rsa->setHash($this->getHashAlgorithm());
            $rsa->setMGFHash($this->getHashAlgorithm());
        }
        $rsa->setEncryptionMode($this->getEncryptionMethod());

        return $rsa->decrypt($data);
    }

    public function isPrivate()
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));

        return $rsa->getPrivateKey() !== null;
    }

    protected function getHashAlgorithm()
    {
        $alg = $this->getValue('alg');
        switch ($alg) {
            case 'RSA-OAEP':
                return 'sha1';
            case 'RSA-OAEP-256':
                return 'sha256';
            default:
                throw new \Exception("Algorithm $alg is not supported");
        }
    }

    /**
     * @return integer
     */
    protected function getEncryptionMethod()
    {
        $alg = $this->getValue('alg');
        switch ($alg) {
            case 'RSA1_5':
                return CRYPT_RSA_ENCRYPTION_PKCS1;
            case 'RSA-OAEP':
            case 'RSA-OAEP-256':
                return CRYPT_RSA_ENCRYPTION_OAEP;
            default:
                throw new \Exception("Algorithm $alg is not supported");
        }
    }

    protected function getKeyData($all = false)
    {
        $result = array();
        if ($all === true) {
            $keys = array('n','e','p','d','q','dp','dq','qi');
        } else {
            $keys = array('n','e');
        }
        foreach ($keys as $key) {
            $value = $this->getValue($key);
            if (null !== $value) {
                $result[$key] = $value;
            }
        }

        return $result;
    }
}
