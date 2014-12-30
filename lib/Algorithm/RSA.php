<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\Util\RSAConverter;

/**
 * This class handles
 *     - signatures PS256/RS256, PS384/RS384 and PS512/RS512.
 *     - encryption of CEK using RSA, RSA-OAEP or RSA-OAEP-256.
 */
abstract class RSA implements JWKInterface, SignatureInterface, VerificationInterface, KeyEncryptionInterface, KeyDecryptionInterface
{
    public function toPublic()
    {
        $values = $this->getValues();

        $keys = array('p', 'd', 'q', 'dp', 'dq', 'qi');
        foreach ($keys as $key) {
            if (isset($values[$key])) {
                unset($values[$key]);
            }
        }

        return $values;
    }

    /**
     * @inheritdoc
     */
    public function encryptKey($cek, array &$header = array(), JWKInterface $sender_key = null)
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(false));

        if ($this->getEncryptionMethod($header) === CRYPT_RSA_ENCRYPTION_OAEP) {
            $rsa->setHash($this->getHashAlgorithm($header));
            $rsa->setMGFHash($this->getHashAlgorithm($header));
        }
        $rsa->setEncryptionMode($this->getEncryptionMethod($header));

        return $rsa->encrypt($cek);
    }

    /**
     * @inheritdoc
     */
    public function decryptKey($encrypted_key, array $header = array())
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));
        if (!$this->isPrivate()) {
            throw new \Exception("The private key is missing");
        }

        if ($this->getEncryptionMethod($header) === CRYPT_RSA_ENCRYPTION_OAEP) {
            $rsa->setHash($this->getHashAlgorithm($header));
            $rsa->setMGFHash($this->getHashAlgorithm($header));
        }
        $rsa->setEncryptionMode($this->getEncryptionMethod($header));

        return $rsa->decrypt($encrypted_key);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(false));

        $rsa->setHash($this->getHashAlgorithm($header));
        if ($this->getSignatureMethod($header) === CRYPT_RSA_SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getHashAlgorithm($header));
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod($header));

        return $rsa->verify($data, $signature);
    }

    /**
     * @inheritdoc
     */
    public function sign($data, array $header = array())
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));
        if (!$this->isPrivate()) {
            throw new \Exception("The private key is missing");
        }

        $rsa->setHash($this->getHashAlgorithm($header));
        if ($this->getSignatureMethod($header) === CRYPT_RSA_SIGNATURE_PSS) {
            $rsa->setMGFHash($this->getHashAlgorithm($header));
            $rsa->setSaltLength(0);
        }
        $rsa->setSignatureMode($this->getSignatureMethod($header));

        $result = $rsa->sign($data);
        if ($result === false) {
            throw new \Exception("An error occured during the creation of the signature");
        }

        return $result;
    }

    public function isPrivate()
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));

        return $rsa->getPrivateKey() !== null;
    }

    public function isPublic()
    {
        $rsa = RSAConverter::fromArrayToRSA_Crypt($this->getKeyData(true));

        return $rsa->getPublicKey() !== null;
    }

    protected function getAlgorithm($header)
    {
        if (isset($header['alg']) && $header['alg'] !== null) {
            return $header['alg'];
        }

        return $this->getValue('alg');
    }

    /**
     * @return integer
     */
    protected function getEncryptionMethod($header)
    {
        $alg = $this->getAlgorithm($header);
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

    protected function getHashAlgorithm($header)
    {
        $alg = $this->getAlgorithm($header);
        switch ($alg) {
            case 'RSA-OAEP':
                return 'sha1';
            case 'RS256':
            case 'PS256':
            case 'RSA-OAEP-256':
                return 'sha256';
            case 'RS384':
            case 'PS384':
                return 'sha384';
            case 'RS512':
            case 'PS512':
                return 'sha512';
            default:
                throw new \Exception("Algorithm '$alg' is not supported");
        }
    }

    /**
     * @return integer
     */
    protected function getSignatureMethod($header)
    {
        $alg = $this->getAlgorithm($header);
        switch ($alg) {
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return CRYPT_RSA_SIGNATURE_PKCS1;
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return CRYPT_RSA_SIGNATURE_PSS;
            default:
                throw new \Exception("Algorithm '$alg' is not supported");
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
