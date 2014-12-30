<?php

namespace SpomkyLabs\JOSE\Algorithm;

use Jose\JWK;
use Jose\JWKInterface;
use Jose\KeyOperation\KeyEncryptionInterface;
use Jose\KeyOperation\KeyDecryptionInterface;

/**
 */
class Dir implements JWKInterface, KeyEncryptionInterface, KeyDecryptionInterface
{
    use JWK;

    protected $values = array('kty' => 'dir');

    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }

    public function toPublic()
    {
        return $this->getValues();
    }

    /**
     * @inheritdoc
     */
    public function encryptKey($cek, array &$header = array(), JWKInterface $sender_key = null)
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function decryptKey($encrypted_cek, array $header = array(), JWKInterface $sender_key = null)
    {
        return $this->getValue('dir');
    }

    public function isPrivate()
    {
        return true;
    }

    public function isPublic()
    {
        return true;
    }
}
