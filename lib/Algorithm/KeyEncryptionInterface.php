<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

interface KeyEncryptionInterface
{
    /**
     * @return string|false
     */
    public function encryptKey($cek, array &$header = array(), JWKInterface $sender_key = null);
}
