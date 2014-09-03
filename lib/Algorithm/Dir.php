<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

/**
 */
abstract class Dir implements JWKInterface, KeyEncryptionInterface, KeyDecryptionInterface
{
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
